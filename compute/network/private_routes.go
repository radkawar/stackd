package network

import (
	"fmt"
	"net/netip"
	"strings"
)

// PrivateRoute is the Lambda subnet's effective EC2 IPv4 routing authority.
// Only active local targets admit direct native VPC packets. More-specific
// blackholes and targets without a native implementation remain denied.
// External NAT routing is independently admitted by NATRoutes.
type PrivateRoute struct {
	Destination netip.Prefix
	Local       bool
}

func writePrivateAdmission(b *strings.Builder, routes []PrivateRoute, direction, pool string) {
	if len(routes) == 0 {
		return
	}
	field := "daddr"
	if direction == "to" {
		field = "saddr"
	}
	fmt.Fprintf(b, "ip %s %s jump private_%s\n", field, pool, direction)
}

func writePrivateChains(b *strings.Builder, routes []PrivateRoute) {
	if len(routes) == 0 {
		return
	}
	for _, direction := range []string{"from", "to"} {
		field := "daddr"
		if direction == "to" {
			field = "saddr"
		}
		fmt.Fprintf(b, "chain private_%s {\n", direction)
		for _, route := range routes {
			verdict := "drop"
			if route.Local {
				verdict = "return"
			}
			fmt.Fprintf(b, "ip %s %s counter %s\n", field, route.Destination, verdict)
		}
		b.WriteString("counter drop\n}\n")
	}
}
