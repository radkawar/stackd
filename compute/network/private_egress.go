package network

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// NATRoute permits only an EC2-authoritative IPv4 route backed by an available
// public NAT gateway, its EIP and its subnet's attached Internet gateway. Actual
// outbound translation uses the owned Docker bridge's daemon-host MASQUERADE;
// it does not expose inbound public NAT or promise remote AWS EIP reachability.
// Denied routes preserve more-specific blackhole/non-native targets.
type NATRoute struct {
	Destination     netip.Prefix
	GatewayID       string
	Allowed         bool
	Ingress, Egress []ACLRule
}

func equalNATRoutes(a, b []NATRoute) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Destination != b[i].Destination || a[i].GatewayID != b[i].GatewayID || a[i].Allowed != b[i].Allowed || !slices.Equal(a[i].Ingress, b[i].Ingress) || !slices.Equal(a[i].Egress, b[i].Egress) {
			return false
		}
	}
	return true
}

func writeNATChains(b *strings.Builder, routes []NATRoute) {
	for i, route := range routes {
		if !route.Allowed {
			continue
		}
		for _, direction := range []string{"from", "to"} {
			field, acl := "daddr", route.Egress
			if direction == "to" {
				field, acl = "saddr", route.Ingress
			}
			fmt.Fprintf(b, "chain nat_%s_%d {\n", direction, i)
			for _, rule := range acl {
				verdict := "drop"
				if rule.Allow {
					verdict = "return"
				}
				fmt.Fprintf(b, "%s counter %s\n", nftIPMatch(rule.Rule, field), verdict)
			}
			b.WriteString("counter drop\n}\n")
		}
	}
}

func writeNATAdmission(b *strings.Builder, routes []NATRoute, direction string) {
	field, state := "daddr", ""
	if direction == "to" {
		field, state = "saddr", "ct state established,related "
	}
	for i, route := range routes {
		if !route.Allowed {
			fmt.Fprintf(b, "ip %s %s counter drop\n", field, route.Destination)
			continue
		}
		fmt.Fprintf(b, "%sip %s %s jump nat_%s_%d\n", state, field, route.Destination, direction, i)
		fmt.Fprintf(b, "%sip %s %s return\n", state, field, route.Destination)
	}
	b.WriteString("counter drop\n")
}

func (b *Bridges) VerifyPrivateEgress(ctx context.Context, networkID string) error {
	info, err := b.inspect(ctx, bridgeName(networkID), networkID)
	if err != nil {
		return err
	}
	if info.Options["com.docker.network.bridge.enable_ip_masquerade"] == "false" {
		return errors.New("lambda private NAT egress requires the owned Docker bridge's real MASQUERADE")
	}
	if mode := info.Options["com.docker.network.bridge.gateway_mode_ipv4"]; mode != "" && mode != "nat" {
		return errors.New("lambda private NAT egress requires IPv4 Docker NAT bridge mode")
	}
	return nil
}
