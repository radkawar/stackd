package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func flowPolicyFixture() (Specification, Policy, Options) {
	identity := FlowIdentity{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", VPCID: "vpc-flow", SubnetID: "subnet-flow", InterfaceID: "eni-flow"}
	spec := Specification{NetworkID: identity.VPCARN(), FlowIdentity: identity, FlowCaptureNamespace: "flow-tests", Pool: netip.MustParsePrefix("10.91.0.0/16"), Gateway: netip.MustParseAddr("10.91.0.1"), Address: netip.MustParseAddr("10.91.1.10"), MAC: "02:cc:01:02:03:04", DNS: []netip.Addr{netip.MustParseAddr("10.91.7.53")}}
	all := IPRule{CIDR: netip.MustParsePrefix("0.0.0.0/0"), Protocol: -1}
	policy := Policy{Subnet: netip.MustParsePrefix("10.91.1.0/24"), SecurityIngress: []IPRule{all}, SecurityEgress: []IPRule{all}, ACLIngress: []ACLRule{{Rule: all, Number: 100, Allow: true}}, ACLEgress: []ACLRule{{Rule: all, Number: 100, Allow: true}}, PrivateRoutes: []PrivateRoute{{Destination: netip.MustParsePrefix("10.91.2.0/24")}, {Destination: spec.Pool, Local: true}}, NATRoutes: []NATRoute{{Destination: netip.MustParsePrefix("192.0.2.0/24")}, {Destination: netip.MustParsePrefix("0.0.0.0/0"), Allowed: true, Ingress: []ACLRule{{Rule: all, Allow: true}}, Egress: []ACLRule{{Rule: all, Allow: true}}}}}
	options := Options{Guest: true, PublicOwner: "flow-owner", Callback: "10.91.0.1:4567", flow: &policyFlowCapture{namespace: spec.FlowCaptureNamespace, registration: FlowRegistration{Group: 42, Token: "immutabletoken", Generation: "epoch1"}}}
	return spec, policy, options
}

func TestFlowPolicyLogsOnlyTerminalVerdicts(t *testing.T) {
	spec, policy, options := flowPolicyFixture()
	rules, err := Rules("stackd_ec2_abcd", spec, policy, "veth-flow", options)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		`iifname "veth-flow" jump from; iifname "veth-flow" jump flow_from_accept;`,
		`oifname "veth-flow" jump to; oifname "veth-flow" ether daddr 02:cc:01:02:03:04 ip daddr 10.91.1.10 ip option lsrr missing ip option ssrr missing jump flow_to_accept;`,
		"jump acl_from\nct state invalid counter jump flow_from_drop\nct state established,related return",
		"ip daddr 10.91.2.0/24 counter jump flow_from_drop",
		"ip saddr 192.0.2.0/24 counter jump flow_to_drop",
		"chain flow_from_drop { jump flow_from_reject; drop; }",
		"chain flow_to_drop { jump flow_to_reject; drop; }",
		`counter name flow_from_accept log group 42 prefix "sf:immutabletoken:egress:ACCEPT" queue-threshold 1 snaplen 128`,
		`counter name flow_to_reject log group 42 prefix "sf:immutabletoken:ingress:REJECT" queue-threshold 1 snaplen 128`,
	} {
		if !strings.Contains(rules, text) {
			t.Fatalf("missing verdict boundary %q", text)
		}
	}
	// Only the four bridge action/direction observation chains and two netdev
	// reject chains contain log statements. No ACL, SG, NAT or route return logs.
	if strings.Count(rules, " log group ") != 6 {
		t.Fatalf("unexpected observation sites: %s", rules)
	}
	for _, direction := range []string{"from", "to"} {
		start := strings.Index(rules, "chain "+direction+" {\n")
		if start < 0 {
			t.Fatalf("missing complete policy chain: %s", direction)
		}
		end := strings.Index(rules[start:], "\n}\n") + start
		if end < start || strings.Contains(rules[start:end], "flow_"+direction+"_accept") {
			t.Fatalf("intermediate return observed as ACCEPT: %s", direction)
		}
	}
	if strings.Contains(rules, "queue num") || strings.Contains(rules, "limit rate") {
		t.Fatal("capture became a packet-admission dependency or sampled coverage")
	}
}

func TestFlowEligibilityExcludesProviderButNotCustomDNS(t *testing.T) {
	spec, _, options := flowPolicyFixture()
	var rules strings.Builder
	writeFlowExclusions(&rules, spec, options)
	text := rules.String()
	for _, exclusion := range []string{
		"ether type != ip return", "169.254.169.254", "169.254.169.123",
		"ip daddr { 10.91.0.2, 169.254.169.253 } udp dport 53 return",
		"ip saddr { 10.91.0.2, 169.254.169.253 } tcp sport 53 return",
		"udp sport 68 udp dport 67 return", "udp sport 67 udp dport 68 return",
		"ip daddr { 169.254.169.250, 169.254.169.251 } tcp dport 1688 return",
		"ip daddr 10.91.0.1 tcp dport 4567 return",
	} {
		if !strings.Contains(text, exclusion) {
			t.Fatalf("missing eligibility exclusion %q", exclusion)
		}
	}
	if strings.Contains(text, "10.91.7.53") || strings.Contains(text, "\nudp dport 53 return") || strings.Contains(text, "169.254.0.0/16") {
		t.Fatalf("ordinary traffic was over-excluded: %s", text)
	}
}

func TestFlowGatewayApplicationPeerIsNotProviderTraffic(t *testing.T) {
	spec, policy, options := flowPolicyFixture()
	options.Callback = ""
	var exclusions strings.Builder
	writeFlowExclusions(&exclusions, spec, options)
	// The public /32 DNAT path can present the host-local client's source as
	// this gateway. Neither ordinary request nor reply may be address-excluded.
	if strings.Contains(exclusions.String(), spec.Gateway.String()) {
		t.Fatalf("host-local application peer was classified as provider traffic: %s", exclusions.String())
	}
	rules, err := Rules("stackd_ec2_abcd", spec, policy, "veth-flow", options)
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{"from", "to"} {
		if !strings.Contains(rules, "counter name flow_"+direction+"_accept log group 42") {
			t.Fatalf("gateway application direction lacks a counted observation: %s", direction)
		}
	}
}

func TestFlowAbsentPreservesOriginalNativePolicy(t *testing.T) {
	spec, policy, options := flowPolicyFixture()
	options.flow = nil
	spec.FlowCaptureNamespace = ""
	rules, err := Rules("stackd_ec2_abcd", spec, policy, "veth-flow", options)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rules, "flow_") || strings.Contains(rules, "log group") {
		t.Fatal("unconfigured attachment gained capture rules")
	}
	for _, text := range []string{"ct state invalid counter drop\nct state established,related return", "ip daddr 10.91.2.0/24 counter drop", `iifname "veth-flow" jump from; oifname "veth-flow" jump to;`} {
		if !strings.Contains(rules, text) {
			t.Fatalf("old policy changed: missing %q", text)
		}
	}
	// Namespace configuration is independent of whether any subscription exists.
	spec.FlowCaptureNamespace = "late-subscription"
	other, err := Rules("stackd_ec2_abcd", spec, policy, "veth-flow", options)
	if err != nil || other != rules {
		t.Fatal("control-plane subscription configuration changed authorization")
	}
}

type policyTestCollector struct {
	bindings    []FlowBinding
	retired     []FlowRegistration
	gaps        []FlowGap
	reconciled  []FlowReconcile
	registerErr error
}

func (c *policyTestCollector) Register(_ context.Context, b FlowBinding) (FlowRegistration, error) {
	c.bindings = append(c.bindings, b)
	return FlowRegistration{Group: 42, Token: "newtoken", Generation: b.Generation}, c.registerErr
}
func (c *policyTestCollector) Retire(_ context.Context, r FlowRegistration) error {
	c.retired = append(c.retired, r)
	return nil
}
func (c *policyTestCollector) Reconcile(_ context.Context, operation FlowReconcile) error {
	c.reconciled = append(c.reconciled, operation)
	return nil
}
func (c *policyTestCollector) Gap(_ context.Context, g FlowGap) error {
	c.gaps = append(c.gaps, g)
	return nil
}
func (*policyTestCollector) Read(context.Context, uint64, FlowReadLimits) (FlowBatch, error) {
	return FlowBatch{}, nil
}
func (*policyTestCollector) Ack(context.Context, uint64) error          { return nil }
func (*policyTestCollector) Health(context.Context) (FlowHealth, error) { return FlowHealth{}, nil }
func (*policyTestCollector) Close() error                               { return nil }

func TestFlowRegistrationBindsAuthoritativeAttachmentBeforeRendering(t *testing.T) {
	spec, _, options := flowPolicyFixture()
	collector := &policyTestCollector{}
	bridges := &Bridges{flowCollectors: map[string]NativeFlowCollector{spec.FlowCaptureNamespace: collector}}
	first := bridges.registerPolicyFlow(t.Context(), "stackd_ec2_abcd", spec, "veth-flow", options, Bridge{Device: "br-owned"})
	second := bridges.registerPolicyFlow(t.Context(), "stackd_ec2_abcd", spec, "veth-flow", options, Bridge{Device: "br-owned"})
	if first == nil || second == nil || first.registration.Generation == second.registration.Generation {
		t.Fatal("replacement reused an immutable capture epoch")
	}
	binding := collector.bindings[0]
	if binding.Identity != spec.FlowIdentity || binding.NetworkID != spec.NetworkID || binding.PolicyTable != "stackd_ec2_abcd" || binding.Bridge != "br-owned" || binding.PeerName != "veth-flow" || binding.PublicOwner != options.PublicOwner || binding.Address != spec.Address || binding.MAC != spec.MAC {
		t.Fatalf("registration lost authoritative ownership: %+v", binding)
	}
	collector.registerErr = errors.New("receiver unavailable")
	if bridges.registerPolicyFlow(t.Context(), "stackd_ec2_abcd", spec, "veth-flow", options, Bridge{Device: "br-owned"}) != nil || len(collector.gaps) != 1 {
		t.Fatal("failed registration did not preserve an honest capture gap")
	}
}

func TestFlowReplacementRetiresOnlyUnreferencedCurrentGeneration(t *testing.T) {
	collector := &policyTestCollector{}
	bridges := &Bridges{flowCollectors: map[string]NativeFlowCollector{"flow-tests": collector}}
	output := []byte(fmt.Sprintf("STACKD_FLOW_POLICY retire sf:%x:currenttoken:epoch1\nSTACKD_FLOW_POLICY gap sf:%x:formerowner:epoch0\n", "flow-tests", "flow-tests"))
	bridges.finishPolicyFlow(t.Context(), "flow-tests", time.Now(), output, nil)
	if len(collector.retired) != 1 || collector.retired[0].Token != "currenttoken" {
		t.Fatalf("retired still-referenced reassociated owner: %+v", collector.retired)
	}
	if len(collector.gaps) != 1 || collector.gaps[0].Token != "" {
		t.Fatal("replacement/quarantine uncertainty was not preserved for affected bindings")
	}
	collector.retired, collector.gaps = nil, nil
	bridges.finishPolicyFlow(t.Context(), "flow-tests", time.Now(), output, errors.New("admitted operation disconnected"))
	if len(collector.retired) != 0 || len(collector.gaps) != 1 {
		t.Fatal("uncertain native completion retired a possibly referenced token or concealed its gap")
	}
	for _, text := range []string{"STACKD_FLOW_POLICY retire sf:zz:token:epoch", "STACKD_FLOW_POLICY retire sf:666f6f:bad/token:epoch", "STACKD_FLOW_POLICY retired sf:666f6f:token:epoch"} {
		if _, ok := parsePolicyFlowWitness(text); ok {
			t.Fatalf("invalid native witness accepted: %s", text)
		}
	}
}

func TestFlowNamespaceWitnessIsBoundedAndRecoverable(t *testing.T) {
	spec, policy, options := flowPolicyFixture()
	options.flow.namespace = strings.Repeat("é", 128) // 256 UTF-8 bytes.
	options.flow.registration.Token = strings.Repeat("a", 32)
	options.flow.registration.Generation = strings.Repeat("b", 26)
	rules, err := Rules("stackd_ec2_abcd", spec, policy, "veth-flow", options)
	if err != nil {
		t.Fatal(err)
	}
	var reconstructed strings.Builder
	for _, line := range strings.Split(rules, "\n") {
		if strings.HasPrefix(line, "chain flow_identity ") {
			fields := strings.Split(line, "\"")
			if len(fields) != 3 || len(fields[1]) > 128 {
				t.Fatalf("identity exceeds bounded nft comment userdata: %s", line)
			}
		}
		if strings.HasPrefix(line, "chain flow_namespace_") {
			fields := strings.Split(line, "\"")
			if len(fields) != 3 || len(fields[1]) > 64 {
				t.Fatalf("oversized or invalid namespace chunk: %s", line)
			}
			reconstructed.WriteString(fields[1])
		}
		if line == "chain source { type filter hook ingress device \"veth-flow\" priority -500; policy drop;" {
			break
		}
	}
	if reconstructed.String() != fmt.Sprintf("%x", options.flow.namespace) {
		t.Fatal("bounded native witness lost its exact UTF-8 namespace")
	}
}

func TestFlowReconciliationUsesCommittedGenerationAndExactRemoval(t *testing.T) {
	current, other := &policyTestCollector{}, &policyTestCollector{}
	bridges := &Bridges{flowCollectors: map[string]NativeFlowCollector{"flow-tests": current, "other": other}}
	capture := &policyFlowCapture{namespace: "flow-tests", registration: FlowRegistration{Group: 42, Token: "committedtoken", Generation: "epoch2"}}
	bridges.reconcilePolicyFlow(t.Context(), "stackd_ec2_abcd", "owner", capture, nil, false)
	if len(current.reconciled) != 1 || current.reconciled[0].Through != capture.registration || current.reconciled[0].PolicyTable != "stackd_ec2_abcd" || current.reconciled[0].PublicOwner != "owner" || len(other.reconciled) != 0 {
		t.Fatalf("replacement reconciliation lost its committed generation cutoff: %+v", current.reconciled)
	}
	bridges.reconcilePolicyFlow(t.Context(), "stackd_ec2_abcd", "owner", nil, nil, false)
	if len(current.reconciled) != 1 {
		t.Fatal("failed capture registration authorized an unbounded reconciliation")
	}
	bridges.reconcilePolicyFlow(t.Context(), "stackd_ec2_abcd", "owner", nil, nil, true)
	if len(current.reconciled) != 2 || current.reconciled[1].Through != (FlowRegistration{}) || len(other.reconciled) != 1 || other.reconciled[0].PolicyTable != "stackd_ec2_abcd" || other.reconciled[0].PublicOwner != "owner" {
		t.Fatal("successful removal did not reconcile known namespaces with exact table/owner authority")
	}
}

func TestFlowRemovalDiscoversExactRetainedCollectorAfterRestart(t *testing.T) {
	var exactName string
	client := existingBridgeClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/containers/json" || r.URL.Query().Get("all") != "true" {
			t.Errorf("removal discovery attempted an unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var filters map[string][]string
		if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil || len(filters["label"]) != 1 || filters["label"][0] != "stackd.network.flows.namespace" {
			t.Error("retained discovery did not select labeled flow receivers")
		}
		json.NewEncoder(w).Encode([]map[string]any{
			{"Names": []string{"/" + exactName}, "Labels": map[string]string{"stackd.network.flows.namespace": "retained"}},
			{"Names": []string{"/foreign-application"}, "Labels": map[string]string{"stackd.network.flows.namespace": "spoofed"}},
			{"Names": []string{"/stackd-flow-bootstrap"}, "Labels": map[string]string{"stackd.network.flows.namespace": "temporary"}},
		})
	})
	candidate, err := NewDockerFlowCollector(client, "retained")
	if err != nil {
		t.Fatal(err)
	}
	exactName = candidate.name
	bridges := &Bridges{client: client, flowCollectors: map[string]NativeFlowCollector{"cached": &policyTestCollector{}}}
	namespaces := bridges.retainedFlowNamespaces(t.Context())
	if len(namespaces) != 2 {
		t.Fatalf("retained discovery admitted foreign/bootstrap containers or lost cached identity: %v", namespaces)
	}
	if _, ok := namespaces["retained"]; !ok {
		t.Fatal("restarted removal could not find its retained registration journal")
	}
	if _, ok := namespaces["cached"]; !ok {
		t.Fatal("retained discovery lost an already admitted manager")
	}
}

func TestFlowForwardHooksOrderSourceAdmissionBeforeDestination(t *testing.T) {
	spec, policy, options := flowPolicyFixture()
	for _, peer := range []string{"veth-source", "veth-destination"} {
		rules, err := Rules("stackd_ec2_abcd", spec, policy, peer, options)
		if err != nil {
			t.Fatal(err)
		}
		sourcePrefix := "chain forward_from { type filter hook forward priority -1; policy accept; "
		destinationPrefix := "chain forward_to { type filter hook forward priority 1; policy accept; "
		var source, destination string
		for _, line := range strings.Split(rules, "\n") {
			if strings.HasPrefix(line, sourcePrefix) {
				source = line
			}
			if strings.HasPrefix(line, destinationPrefix) {
				destination = line
			}
		}
		if source == "" || destination == "" {
			t.Fatalf("independent ENI tables may evaluate at the same forward priority: %s", peer)
		}
		if !strings.Contains(source, fmt.Sprintf("iifname %q jump from; iifname %q jump flow_from_accept;", peer, peer)) || strings.Contains(source, "jump to;") || strings.Contains(source, "flow_to_accept") {
			t.Fatalf("source admission/observation phase includes destination authorization: %s", source)
		}
		if !strings.Contains(destination, fmt.Sprintf("oifname %q jump to;", peer)) || !strings.Contains(destination, "jump flow_to_accept;") || strings.Contains(destination, "jump from;") || strings.Contains(destination, "flow_from_accept") {
			t.Fatalf("destination observation can precede complete source admission: %s", destination)
		}
		if strings.Contains(rules, "chain forward { type filter hook forward priority 0;") {
			t.Fatal("captured policy retained an unordered mixed-direction forward hook")
		}
	}
}
