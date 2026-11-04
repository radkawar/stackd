package elbv2

import (
	"net/netip"
	"testing"

	"stackd/compute/network"
)

func TestClonePolicyDetachesPodAndExistingRouteAuthority(t *testing.T) {
	original := network.Policy{
		PodRoutes:     []network.PodRoute{{Prefix: netip.MustParsePrefix("10.42.0.0/24"), NodeUID: "current-node"}},
		PrivateRoutes: []network.PrivateRoute{{Destination: netip.MustParsePrefix("10.0.0.0/16"), Local: true}},
		NATRoutes:     []network.NATRoute{{Ingress: []network.ACLRule{{Number: 100}}, Egress: []network.ACLRule{{Number: 200}}}},
	}
	cloned := clonePolicy(original)
	cloned.PodRoutes[0].NodeUID = "recreated-node"
	cloned.PrivateRoutes[0].Local = false
	cloned.NATRoutes[0].Ingress[0].Number = 1
	cloned.NATRoutes[0].Egress[0].Number = 2
	if original.PodRoutes[0].NodeUID != "current-node" || !original.PrivateRoutes[0].Local || original.NATRoutes[0].Ingress[0].Number != 100 || original.NATRoutes[0].Egress[0].Number != 200 {
		t.Fatal("ALB snapshot aliases caller-owned native route authority")
	}
}
