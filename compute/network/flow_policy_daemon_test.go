package network

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"stackd/compute/docker"
)

// This test uses real bridge/veth traffic and NFLOG; client send success is not
// used as a verdict assertion. The destination intentionally has no application
// listener: ACCEPT means this ENI admitted the datagram, not remote success.
func TestDaemonFlowPolicyActualAdmissionAndTerminalRejection(t *testing.T) {
	client := daemonNetworkTestEngine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	bridges, err := NewDaemonBridges(client)
	if err != nil {
		t.Fatal(err)
	}
	namespace := "native-flow-policy-" + rand.Text()
	collector, err := NewDockerFlowCollector(client, namespace)
	if err != nil {
		t.Fatal(err)
	}
	identity := FlowIdentity{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", VPCID: "vpc-" + rand.Text(), SubnetID: "subnet-source", InterfaceID: "eni-source"}
	base := Specification{NetworkID: identity.VPCARN(), FlowIdentity: identity, FlowCaptureNamespace: namespace, Pool: netip.MustParsePrefix("10.254.246.0/24"), Gateway: netip.MustParseAddr("10.254.246.1"), Address: netip.MustParseAddr("10.254.246.10"), MAC: "02:cc:fe:f6:00:0a"}
	type endpoint struct {
		spec                   Specification
		container, table, peer string
		policy                 Policy
	}
	endpoints := make([]endpoint, 2)
	var bridge Bridge
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), time.Minute)
		defer done()
		for _, endpoint := range endpoints {
			if endpoint.table != "" {
				if err := bridges.RemovePolicy(cleanup, endpoint.table, namespace); err != nil {
					t.Error(err)
				}
			}
			if endpoint.container != "" {
				if err := client.RemoveContainer(cleanup, endpoint.container); err != nil {
					t.Error(err)
				}
			}
		}
		if err := bridges.Release(cleanup, base.NetworkID); err != nil {
			t.Error(err)
		}
		// Production Close retains the process/volume. Only this test's exact,
		// randomly namespaced resources are explicitly destroyed by its owner.
		if err := client.RemoveContainer(cleanup, collector.name); err != nil {
			t.Error(err)
		}
		if err := client.JSON(cleanup, "DELETE", "/volumes/"+collector.volume, nil, nil); err != nil {
			t.Error(err)
		}
	})
	if err := collector.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	if err := bridges.WithBridge(ctx, base, func(value Bridge) error { bridge = value; return nil }); err != nil {
		t.Fatal(err)
	}
	all := IPRule{CIDR: netip.MustParsePrefix("0.0.0.0/0"), Protocol: -1}
	for i := range endpoints {
		endpoint := &endpoints[i]
		endpoint.spec = base
		endpoint.spec.FlowIdentity.SubnetID = fmt.Sprintf("subnet-native-%d", i)
		endpoint.spec.FlowIdentity.InterfaceID = fmt.Sprintf("eni-native-%d", i)
		subnet := "10.254.246.0/28"
		if i == 1 {
			endpoint.spec.Address = netip.MustParseAddr("10.254.246.30")
			endpoint.spec.MAC = "02:cc:fe:f6:00:1e"
			subnet = "10.254.246.16/28"
		}
		endpoint.policy = Policy{Subnet: netip.MustParsePrefix(subnet), SecurityIngress: []IPRule{all}, SecurityEgress: []IPRule{all}, ACLIngress: []ACLRule{{Rule: all, Number: 100, Allow: true}}, ACLEgress: []ACLRule{{Rule: all, Number: 100, Allow: true}}}
		endpoint.container = fmt.Sprintf("stackd-flow-endpoint-%d-%s", i, rand.Text())
		config := docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: []string{"sleep"}, Cmd: []string{"240"}, NetworkingConfig: &docker.ContainerNetworkingConfig{EndpointsConfig: map[string]docker.ContainerEndpointConfig{bridge.Name: {MacAddress: endpoint.spec.MAC, IPAMConfig: docker.ContainerEndpointIPAMConfig{IPv4Address: endpoint.spec.Address.String()}}}}, HostConfig: docker.ContainerHostConfig{NetworkMode: bridge.Name, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32}}
		if err := client.JSON(ctx, "POST", "/containers/create?name="+endpoint.container, config, nil); err != nil {
			t.Fatal(err)
		}
		if err := client.JSON(ctx, "POST", "/containers/"+endpoint.container+"/start", nil, nil); err != nil {
			t.Fatal(err)
		}
		output, err := docker.RunHelper(ctx, client, "flow-peer-index", docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: []string{"cat", "/sys/class/net/eth0/iflink"}, HostConfig: docker.ContainerHostConfig{NetworkMode: "container:" + endpoint.container, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}}})
		if err != nil {
			t.Fatal(err)
		}
		index, err := strconv.Atoi(strings.TrimSpace(string(output)))
		if err != nil {
			t.Fatal(err)
		}
		output, err = docker.RunHelper(ctx, client, "flow-peer-name", docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: []string{"ip", "-j", "link", "show", "master", bridge.Device}, HostConfig: docker.ContainerHostConfig{NetworkMode: "host", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}}})
		if err != nil {
			t.Fatal(err)
		}
		var links []struct {
			IfIndex int    `json:"ifindex"`
			IfName  string `json:"ifname"`
		}
		if err := json.Unmarshal(output, &links); err != nil {
			t.Fatal(err)
		}
		for _, link := range links {
			if link.IfIndex == index {
				endpoint.peer = link.IfName
			}
		}
		if endpoint.peer == "" {
			t.Fatal("native endpoint lacks its exact retained bridge peer")
		}
		endpoint.table = fmt.Sprintf("stackd_ec2_%x", sha256.Sum256([]byte(endpoint.container)))
		if err := bridges.ApplyPolicy(ctx, endpoint.table, endpoint.spec, endpoint.policy, endpoint.peer, Options{PublicOwner: namespace}, bridge); err != nil {
			t.Fatal(err)
		}
	}
	// A distinct manager, opened after the ENIs are running, must adopt the
	// already configured receiver rather than require a policy mutation.
	late, err := NewDockerFlowCollector(client, namespace)
	if err != nil {
		t.Fatal(err)
	}
	if err := late.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	firstHealth, err := collector.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lateHealth, err := late.Health(ctx)
	if err != nil || !lateHealth.Ready || lateHealth.EngineID != firstHealth.EngineID || lateHealth.BootID != firstHealth.BootID || lateHealth.Group != firstHealth.Group {
		t.Fatalf("late manager changed daemon collector identity: %+v / %+v, %v", firstHealth, lateHealth, err)
	}
	var cursor uint64
	cases := []struct {
		name                                                                string
		sourceReject, destinationReject, aclReject, privateReject, hostPeer bool
	}{
		{name: "accepted-without-remote-listener"},
		{name: "destination-security-group", destinationReject: true},
		{name: "destination-ordered-network-acl", destinationReject: true, aclReject: true},
		{name: "source-security-group", sourceReject: true},
		{name: "source-private-route-blackhole", sourceReject: true, privateReject: true},
		{name: "gateway-address-is-ordinary-application-peer", hostPeer: true},
	}
	for i, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			for j := range endpoints {
				endpoint := &endpoints[j]
				endpoint.policy.SecurityIngress, endpoint.policy.SecurityEgress = []IPRule{all}, []IPRule{all}
				endpoint.policy.ACLIngress = []ACLRule{{Rule: all, Number: 100, Allow: true}}
				endpoint.policy.PrivateRoutes = nil
				if j == 0 && scenario.sourceReject && !scenario.privateReject {
					endpoint.policy.SecurityEgress = nil
				}
				if j == 0 && scenario.privateReject {
					endpoint.policy.PrivateRoutes = []PrivateRoute{{Destination: netip.MustParsePrefix("10.254.246.16/28")}, {Destination: base.Pool, Local: true}}
				}
				if j == 1 && scenario.destinationReject {
					if scenario.aclReject {
						endpoint.policy.ACLIngress = []ACLRule{{Rule: all, Number: 50, Allow: false}, {Rule: all, Number: 100, Allow: true}}
					} else {
						endpoint.policy.SecurityIngress = nil
					}
				}
				if err := bridges.ApplyPolicy(ctx, endpoint.table, endpoint.spec, endpoint.policy, endpoint.peer, Options{PublicOwner: namespace}, bridge); err != nil {
					t.Fatal(err)
				}
			}
			sourcePort, destinationPort := 32000+i, 33000+i
			sourceAddress, sourceNetwork := endpoints[0].spec.Address, "container:"+endpoints[0].container
			if scenario.hostPeer {
				// This is the same gateway-address application tuple that the
				// supported host-local public /32 DNAT path presents to the ENI.
				sourceAddress, sourceNetwork = base.Gateway, "host"
			}
			script := fmt.Sprintf("import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind((%q,%d))\ns.sendto(b'flow',(%q,%d))\n", sourceAddress.String(), sourcePort, endpoints[1].spec.Address.String(), destinationPort)
			if _, err := docker.RunHelper(ctx, client, "flow-real-datagram", docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: []string{"python3", "-c", script}, HostConfig: docker.ContainerHostConfig{NetworkMode: sourceNetwork, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}}}); err != nil {
				t.Fatal(err)
			}
			want := map[string]int{endpoints[0].spec.FlowIdentity.InterfaceID + ":egress:ACCEPT": 1}
			if scenario.sourceReject {
				want = map[string]int{endpoints[0].spec.FlowIdentity.InterfaceID + ":egress:REJECT": 1}
			} else {
				action := "ACCEPT"
				if scenario.destinationReject {
					action = "REJECT"
				}
				want[endpoints[1].spec.FlowIdentity.InterfaceID+":ingress:"+action] = 1
			}
			if scenario.hostPeer {
				delete(want, endpoints[0].spec.FlowIdentity.InterfaceID+":egress:ACCEPT")
			}
			seen := make(map[string]int)
			deadline := time.NewTimer(8 * time.Second)
			defer deadline.Stop()
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			var complete time.Time
			for {
				batch, err := late.Read(ctx, cursor, FlowReadLimits{MaxRecords: 512, MaxBytes: 512 << 10})
				if err != nil {
					t.Fatal(err)
				}
				for _, record := range batch.Records {
					observation := record.Observation
					if observation == nil || observation.Protocol != 17 || int(observation.SourcePort) != sourcePort || int(observation.DestinationPort) != destinationPort {
						continue
					}
					if observation.Binding.Identity.VPCARN() != base.NetworkID || observation.SourceAddress != sourceAddress || observation.DestinationAddress != endpoints[1].spec.Address || observation.IPBytes != 32 || observation.Packets != 1 || observation.Token == "" || observation.Generation == "" || observation.ObservedAt.IsZero() {
						t.Fatalf("native evidence lost its actual tuple/length/identity/time: %+v", observation)
					}
					seen[observation.Binding.Identity.InterfaceID+":"+observation.Direction+":"+observation.Action]++
				}
				cursor = batch.Cursor
				if err := late.Ack(ctx, cursor); err != nil {
					t.Fatal(err)
				}
				done := len(seen) == len(want)
				for key, count := range seen {
					if want[key] != count {
						t.Fatalf("duplicate or intermediate native verdict: got %v, want %v", seen, want)
					}
				}
				if done && complete.IsZero() {
					complete = time.Now()
				}
				if !complete.IsZero() && time.Since(complete) >= 500*time.Millisecond {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-deadline.C:
					t.Fatalf("real datagram lacks native verdict evidence: got %v, want %v", seen, want)
				case <-ticker.C:
				}
			}
		})
	}
	if err := collector.Close(); err != nil {
		t.Fatal(err)
	}
	if health, err := late.Health(ctx); err != nil || !health.Ready {
		t.Fatalf("controller Close killed retained collector: %+v, %v", health, err)
	}
}
