package elbv2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"stackd/compute/network"
	api "stackd/internal/awsapi/elbv2"
)

// Provider 6.68.0, c9b83d813022cdd05fc955480b07e269c6e18023:
// internal/service/elbv2/target_group.go:548-577,825-931,1233-1272,1401-1442.
// The attribute expander is called unconditionally, but a minimal HTTP/IP create
// emits ONLY deregistration_delay.timeout_seconds=300. Zero slow_start, false
// proxy_protocol_v2/connection_termination and empty computed algorithm/anomaly/
// cross-zone strings are omitted. Lambda attributes are not emitted for IP or
// instance groups; nullable preserve_client_ip is omitted when null.
// Explicit/default readback updates expand the values below. Stickiness emits
// enabled/type and the matching cookie duration (app_cookie also emits name).
// Health blocks emit count/percentage pairs only when their block is present;
// notably an explicitly empty dns_failover block defaults count to "off", NOT
// the service's default "1", and is intentionally unsupported here.
func TestTargetGroupProviderDefaultAttributeAdmission(t *testing.T) {
	ctx := controlContext(t)
	s := New(Config{Networks: controlNetwork{}})
	defer s.Close()
	group := controlGroup(t, s, ctx, "provider-defaults")
	defaults := [][2]string{
		{"deregistration_delay.timeout_seconds", "300"},
		{"stickiness.enabled", "false"},
		{"stickiness.type", "lb_cookie"},
		{"stickiness.lb_cookie.duration_seconds", "86400"},
		{"stickiness.app_cookie.duration_seconds", "86400"},
		{"stickiness.app_cookie.cookie_name", ""},
		{"slow_start.duration_seconds", "0"},
		{"load_balancing.algorithm.type", "round_robin"},
		{"load_balancing.algorithm.anomaly_mitigation", "off"},
		{"load_balancing.cross_zone.enabled", "use_load_balancer_configuration"},
		{"target_group_health.dns_failover.minimum_healthy_targets.count", "1"},
		{"target_group_health.dns_failover.minimum_healthy_targets.percentage", "off"},
		{"target_group_health.unhealthy_state_routing.minimum_healthy_targets.count", "1"},
		{"target_group_health.unhealthy_state_routing.minimum_healthy_targets.percentage", "off"},
	}
	q := url.Values{"TargetGroupArn": {value(group.TargetGroupArn)}}
	want := make(map[string]string, len(defaults))
	for i, attribute := range defaults {
		prefix := "Attributes.member." + strconv.Itoa(i+1)
		q.Set(prefix+".Key", attribute[0])
		q.Set(prefix+".Value", attribute[1])
		want[attribute[0]] = attribute[1]
	}
	out, err := controlCall(t, s, ctx, "ModifyTargetGroupAttributes", q)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, attribute := range out.(*api.ModifyTargetGroupAttributesOutput).Attributes {
		got[value(attribute.Key)] = value(attribute.Value)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("defaults = %v, want %v", got, want)
	}
	for _, setting := range [][2]string{
		{"stickiness.enabled", "true"},
		{"stickiness.type", "app_cookie"},
		{"stickiness.lb_cookie.duration_seconds", "60"},
		{"stickiness.app_cookie.duration_seconds", "60"},
		{"stickiness.app_cookie.cookie_name", "session"},
		{"slow_start.duration_seconds", "30"},
		{"load_balancing.algorithm.type", "least_outstanding_requests"},
		{"load_balancing.algorithm.type", "weighted_random"},
		{"load_balancing.algorithm.anomaly_mitigation", "on"},
		{"load_balancing.cross_zone.enabled", "false"},
		{"load_balancing.cross_zone.enabled", "true"},
		{"target_group_health.dns_failover.minimum_healthy_targets.count", "off"},
		{"target_group_health.dns_failover.minimum_healthy_targets.count", "2"},
		{"target_group_health.dns_failover.minimum_healthy_targets.percentage", "50"},
		{"target_group_health.unhealthy_state_routing.minimum_healthy_targets.count", "2"},
		{"target_group_health.unhealthy_state_routing.minimum_healthy_targets.percentage", "50"},
		{"proxy_protocol_v2.enabled", "false"},
		{"preserve_client_ip.enabled", "true"},
		{"deregistration_delay.connection_termination.enabled", "false"},
		{"lambda.multi_value_headers.enabled", "false"},
	} {
		_, err := controlCall(t, s, ctx, "ModifyTargetGroupAttributes", url.Values{
			"TargetGroupArn":          {value(group.TargetGroupArn)},
			"Attributes.member.1.Key": {"deregistration_delay.timeout_seconds"}, "Attributes.member.1.Value": {"0"},
			"Attributes.member.2.Key": {setting[0]}, "Attributes.member.2.Value": {setting[1]},
		})
		if err == nil || wireError(err).Code != "UnsupportedOperation" {
			t.Fatalf("unimplemented %v admitted: %v", setting, err)
		}
		if err := s.repository.View(ctx, func(tx Reader) error {
			stored, err := tx.TargetGroup(scopeFor(ctx), value(group.TargetGroupArn))
			if err == nil && stored.DeregistrationDelay != 300*time.Second {
				t.Fatal("rejected attribute batch changed draining")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTargetRoundRobinScopeAndConcurrency(t *testing.T) {
	var rotation targetRoundRobin
	scope := Scope{"aws", "111111111111", "us-east-1"}
	other := Scope{"aws", "222222222222", "us-east-1"}
	for draw := range 8 {
		for _, key := range []targetRotationKey{{scope, "a"}, {scope, "b"}, {other, "a"}} {
			if got := rotation.draw(key.Scope, key.groupARN, 2); got != draw%2 {
				t.Fatalf("%v draw %d = %d", key, draw, got)
			}
		}
	}
	var workers sync.WaitGroup
	var mu sync.Mutex
	counts := [3]int{}
	for range 12 {
		workers.Go(func() {
			for range 30 {
				n := rotation.draw(scope, "parallel", 3)
				mu.Lock()
				counts[n]++
				mu.Unlock()
			}
		})
	}
	workers.Wait()
	if counts != [3]int{120, 120, 120} {
		t.Fatal(counts)
	}
	rotation.forget(scope, "parallel")
	if got := rotation.draw(scope, "parallel", 3); got != 0 {
		t.Fatal("deleted group retained rotation", got)
	}
}

type targetEffectKey struct {
	Scope
	id string
}

type targetEffectNetwork struct {
	*dnsNetwork
	endpoints map[targetEffectKey]TargetEndpoint
}

func (n *targetEffectNetwork) ResolveTarget(_ context.Context, scope Scope, _, _, id string) (TargetEndpoint, error) {
	endpoint, ok := n.endpoints[targetEffectKey{scope, id}]
	if !ok {
		return TargetEndpoint{}, ErrNotFound
	}
	return endpoint, nil
}

func targetEffectSetup(t *testing.T) (*Service, *targetEffectNetwork, LoadBalancerRecord, []TargetGroupRecord) {
	t.Helper()
	scope := scopeFor(controlContext(t))
	lb := dnsRecord(scope, "vpc-effects", "internal")
	text(&lb.Data.AvailabilityZones[0].ZoneName, "us-east-1a")
	text(&lb.Data.AvailabilityZones[1].ZoneName, "us-east-1b")
	ensureDNSName(&lb)
	owner := value(lb.Data.LoadBalancerArn)
	networks := &targetEffectNetwork{
		dnsNetwork: &dnsNetwork{attachments: map[string]NetworkAttachment{
			owner + "/eni-a": {ID: "eni-a", Network: network.Specification{Address: netip.MustParseAddr("10.0.1.4")}},
			owner + "/eni-b": {ID: "eni-b", Network: network.Specification{Address: netip.MustParseAddr("10.0.2.4")}},
		}, scopes: map[string]Scope{owner: scope}},
		endpoints: map[targetEffectKey]TargetEndpoint{},
	}
	for i, id := range []string{"10.0.0.8", "10.0.0.9"} {
		networks.endpoints[targetEffectKey{scope, id}] = TargetEndpoint{Address: id, AvailabilityZone: []string{"us-east-1a", "us-east-1b"}[i], OwnerARN: "task/" + id, Incarnation: "eni/" + id}
	}
	s := New(Config{Networks: networks})
	t.Cleanup(func() { s.Close() })
	groups := make([]TargetGroupRecord, 0, 2)
	if err := s.repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutLoadBalancer(lb); err != nil {
			return err
		}
		for _, name := range []string{"blue", "green"} {
			groupARN := arn(scope, "targetgroup/"+name+"/1")
			group := TargetGroupRecord{Scope: scope, DeregistrationDelay: 300 * time.Second, Data: api.TargetGroup{
				TargetGroupArn: new(api.TargetGroupArn(groupARN)), VpcId: new(api.VpcId("vpc-effects")), TargetType: new(api.TargetTypeEnum("ip")), Protocol: new(api.ProtocolEnum("HTTP")), LoadBalancerArns: api.LoadBalancerArns{api.LoadBalancerArn(owner)},
			}}
			defaultHealth(&group.Data)
			if err := tx.PutTargetGroup(group); err != nil {
				return err
			}
			groups = append(groups, group)
			for _, id := range []string{"10.0.0.8", "10.0.0.9"} {
				target := TargetRecord{Scope: scope, TargetGroupARN: groupARN, Data: api.TargetDescription{Id: new(api.TargetId(id)), Port: new(api.Port(8080))}, OwnerARN: "task/" + id, Incarnation: "eni/" + id, State: "healthy", Version: 1, NextCheck: s.clock.Now()}
				if err := tx.PutTarget(target); err != nil {
					return err
				}
			}
			listenerARN := arn(scope, "listener/app/"+name+"/1/1")
			if err := tx.PutListener(ListenerRecord{Scope: scope, Data: api.Listener{ListenerArn: new(api.ListenerArn(listenerARN)), LoadBalancerArn: lb.Data.LoadBalancerArn, Protocol: new(api.ProtocolEnum("HTTP")), Port: new(api.Port(80)), DefaultActions: api.Actions{{Type: new(api.ActionTypeEnum("forward")), TargetGroupArn: group.Data.TargetGroupArn}}}}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return s, networks, lb, groups
}

func targetEffectState(t *testing.T, s *Service, group TargetGroupRecord, id, state string) {
	t.Helper()
	if err := s.repository.Update(t.Context(), func(tx Transaction) error {
		target, err := tx.Target(group.Scope, value(group.Data.TargetGroupArn), id, 8080)
		if err != nil {
			return err
		}
		target.State = state
		return tx.PutTarget(target)
	}); err != nil {
		t.Fatal(err)
	}
}

// Real loopback HTTP requests exercise the native forwarding handler; the
// injected network authority maps VPC identities to local test backends. This
// does not claim EC2 namespace/SG/NACL coverage or external AWS evidence.
func TestTargetDefaultsForwardAcrossZonesWithoutAffinity(t *testing.T) {
	s, networks, lb, groups := targetEffectSetup(t)
	backends := map[string]string{}
	for _, id := range []string{"10.0.0.8", "10.0.0.9"} {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Target", id)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, id)
		}))
		defer backend.Close()
		backends[net.JoinHostPort(id, "8080")] = backend.Listener.Addr().String()
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", backends[address])
	}}
	defer transport.CloseIdleConnections()
	node := &runtimeNode{transport: transport, attachment: NetworkAttachment{SubnetID: "subnet-a"}}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.runtime.serve(w, r, lb.Scope, arn(lb.Scope, "listener/app/"+strings.TrimPrefix(r.URL.Path, "/")+"/1/1"), node)
	}))
	defer front.Close()
	request := func(group, want string, status int) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, front.URL+"/"+group, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Cookie", "AWSALB=previous-target; AWSALBCORS=previous-target; session=sticky")
		response, err := front.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != status || response.Header.Get("X-Target") != want {
			t.Fatalf("%s: status=%d target=%q error=%v", group, response.StatusCode, response.Header.Get("X-Target"), err)
		}
		if response.Header.Get("Set-Cookie") != "" {
			t.Fatal("disabled stickiness generated a cookie")
		}
	}
	for i := range 8 {
		for _, group := range []string{"blue", "green"} {
			request(group, []string{"10.0.0.8", "10.0.0.9"}[i%2], 200)
		}
	}
	// A fresh healthy member immediately shares all requests equally. It is
	// neither slow-started nor suppressed by anomaly weighting.
	targetEffectState(t, s, groups[0], "10.0.0.9", "initial")
	request("blue", "10.0.0.8", 200)
	targetEffectState(t, s, groups[0], "10.0.0.9", "healthy")
	request("blue", "10.0.0.9", 200)
	request("blue", "10.0.0.8", 200)
	// Zero healthy targets activates unhealthy-state routing, never draining.
	targetEffectState(t, s, groups[0], "10.0.0.8", "unhealthy")
	targetEffectState(t, s, groups[0], "10.0.0.9", "unhealthy")
	request("blue", "10.0.0.9", 200)
	request("blue", "10.0.0.8", 200)
	targetEffectState(t, s, groups[0], "10.0.0.9", "draining")
	request("blue", "10.0.0.8", 200)
	// A stale healthy incarnation must not block the eligible unhealthy one.
	targetEffectState(t, s, groups[0], "10.0.0.9", "healthy")
	key := targetEffectKey{lb.Scope, "10.0.0.9"}
	endpoint := networks.endpoints[key]
	endpoint.Incarnation = "replacement"
	networks.endpoints[key] = endpoint
	request("blue", "10.0.0.8", 200)
	targetEffectState(t, s, groups[0], "10.0.0.8", "draining")
	request("blue", "", 503)
	other := lb.Scope
	other.AccountID = "999999999999"
	if _, _, _, err := s.runtime.selectTarget(t.Context(), other, value(groups[0].Data.TargetGroupArn)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("target selection crossed scope: %v", err)
	}
}

func TestTargetDefaultDNSHealthFailoverAndRecovery(t *testing.T) {
	s, networks, lb, groups := targetEffectSetup(t)
	check := func(want ...string) {
		t.Helper()
		if got := dnsAddresses(dnsLookup(t, s, value(lb.Data.DNSName), dnsmessage.TypeA)); !reflect.DeepEqual(got, want) {
			t.Fatalf("DNS = %v, want %v", got, want)
		}
		answers, err := s.LookupDNSAlias(t.Context(), value(lb.Data.DNSName), value(lb.Data.CanonicalHostedZoneId), dnsmessage.TypeA)
		if err != nil || len(answers) != len(want) {
			t.Fatalf("alias failover differs: %v %v", answers, err)
		}
	}
	check("10.0.1.4", "10.0.2.4")
	probe := func(success bool) {
		t.Helper()
		var target TargetRecord
		if err := s.repository.View(t.Context(), func(tx Reader) error {
			var err error
			target, err = tx.Target(lb.Scope, value(groups[0].Data.TargetGroupArn), "10.0.0.8", 8080)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		state := "unhealthy"
		if success {
			state = "healthy"
		}
		if err := s.runtime.commitHealth(t.Context(), target, state, "Target.FailedHealthChecks", "probe", success, true); err != nil {
			t.Fatal(err)
		}
	}
	probe(false)
	check("10.0.1.4", "10.0.2.4") // below health-check failure threshold
	probe(false)
	check("10.0.2.4") // one associated group's zone failure removes that node
	for range 4 {
		probe(true)
	}
	check("10.0.2.4")
	probe(true)
	check("10.0.1.4", "10.0.2.4")
	// Stale healthy identity is not a healthy count for DNS.
	key := targetEffectKey{lb.Scope, "10.0.0.8"}
	original := networks.endpoints[key]
	replacement := original
	replacement.OwnerARN = "task/replacement"
	networks.endpoints[key] = replacement
	check("10.0.2.4")
	networks.endpoints[key] = original
	for _, group := range groups {
		targetEffectState(t, s, group, "10.0.0.8", "unhealthy")
		targetEffectState(t, s, group, "10.0.0.9", "unhealthy")
	}
	check("10.0.1.4", "10.0.2.4") // all-unhealthy DNS fail-open
	for _, group := range groups {
		targetEffectState(t, s, group, "10.0.0.8", "healthy")
	}
	check("10.0.1.4")
	// An out-of-VPC target registered in all zones restores both counts.
	endpoint := networks.endpoints[key]
	endpoint.AvailabilityZone = "all"
	networks.endpoints[key] = endpoint
	check("10.0.1.4", "10.0.2.4")
	// An empty associated group fails open, not an invented healthy target.
	if err := s.repository.Update(t.Context(), func(tx Transaction) error {
		return tx.PutTargetGroup(TargetGroupRecord{Scope: lb.Scope, Data: api.TargetGroup{TargetGroupArn: new(api.TargetGroupArn(arn(lb.Scope, "targetgroup/empty/3"))), LoadBalancerArns: api.LoadBalancerArns{api.LoadBalancerArn(value(lb.Data.LoadBalancerArn))}}})
	}); err != nil {
		t.Fatal(err)
	}
	check("10.0.1.4", "10.0.2.4")
}
