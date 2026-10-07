package network

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPrivateNATAdmissionKeepsBlackholesAndNoInboundNAT(t *testing.T) {
	routes := []NATRoute{{Destination: netip.MustParsePrefix("192.0.2.0/24")}, {Destination: netip.MustParsePrefix("0.0.0.0/0"), GatewayID: "nat-owned", Allowed: true}}
	for _, direction := range []string{"from", "to"} {
		var rules strings.Builder
		writeNATAdmission(&rules, routes, direction)
		text := rules.String()
		field := "daddr"
		if direction == "to" {
			field = "saddr"
		}
		blackhole := "ip " + field + " 192.0.2.0/24 counter drop"
		admitted := "ip " + field + " 0.0.0.0/0 jump nat_" + direction + "_1"
		if strings.Index(text, blackhole) < 0 || strings.Index(text, blackhole) > strings.Index(text, admitted) {
			t.Fatalf("more-specific blackhole was bypassed: %s", text)
		}
		if direction == "to" && !strings.Contains(text, "ct state established,related "+admitted) {
			t.Fatalf("unsolicited inbound private NAT was admitted: %s", text)
		}
		if !strings.HasSuffix(text, "counter drop\n") {
			t.Fatalf("NAT admission is not default deny: %s", text)
		}
	}
}

func TestPrivateRouteAuthorityPrecedesConntrackAndDirectLocalTraffic(t *testing.T) {
	routes := []PrivateRoute{{Destination: netip.MustParsePrefix("10.91.2.0/24")}, {Destination: netip.MustParsePrefix("10.91.0.0/16"), Local: true}, {Destination: netip.MustParsePrefix("0.0.0.0/0")}}
	var chains strings.Builder
	writePrivateChains(&chains, routes)
	text := chains.String()
	for _, field := range []string{"saddr", "daddr"} {
		denied := strings.Index(text, "ip "+field+" 10.91.2.0/24 counter drop")
		local := strings.Index(text, "ip "+field+" 10.91.0.0/16 counter return")
		if denied < 0 || local < 0 || denied > local {
			t.Fatalf("local route bypassed more-specific unsupported target: %s", text)
		}
	}
	if strings.Contains(text, "ct state established") {
		t.Fatalf("route withdrawal can be bypassed by conntrack: %s", text)
	}
}

func TestPacketPolicyEqualityIncludesNativeRouteAuthority(t *testing.T) {
	route := PrivateRoute{Destination: netip.MustParsePrefix("10.91.0.0/16"), Local: true}
	a, b := Policy{PrivateRoutes: []PrivateRoute{route}}, Policy{PrivateRoutes: []PrivateRoute{route}}
	if !a.Equal(b) {
		t.Fatal("equal private routes compare unequal")
	}
	b.PrivateRoutes[0].Local = false
	if a.Equal(b) {
		t.Fatal("private route withdrawal ignored")
	}
	a = Policy{NATRoutes: []NATRoute{{Destination: netip.MustParsePrefix("0.0.0.0/0"), Allowed: true, GatewayID: "nat-immutable"}}}
	b = Policy{NATRoutes: []NATRoute{{Destination: netip.MustParsePrefix("0.0.0.0/0"), Allowed: false, GatewayID: "nat-immutable"}}}
	if a.Equal(b) {
		t.Fatal("NAT owner authority withdrawal ignored")
	}
}
