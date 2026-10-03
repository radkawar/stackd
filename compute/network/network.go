// Package network owns physical attachments and packet policy shared by compute
// runtimes. EC2 retains addresses, topology and authorization state.
package network

import (
	"net/netip"
	"slices"
)

// Specification binds an EC2-owned reservation to a physical attachment.
// NetworkID is the logical VPC identity, not a native endpoint ID. Drivers return
// capability errors rather than silently substituting another address.
type Specification struct {
	NetworkID                  string
	Pool                       netip.Prefix
	Gateway                    netip.Addr
	Address                    netip.Addr
	MAC                        string
	DNS                        []netip.Addr
	NTPServers, NetBIOSServers []netip.Addr
	NetBIOSNodeType            int
	DomainName, Hostname       string
	// PublicHostname is EC2's current public name. VPC DNS resolves it to the
	// private address (split horizon); an empty value withdraws that record.
	PublicHostname string
	DNSSupport     bool
	Policy         Policy
}

// IPRule is a normalized IPv4 packet match. Protocol -1 matches all protocols;
// ICMPType and ICMPCode use -1 for wildcards.
type IPRule struct {
	CIDR               netip.Prefix
	Protocol           int
	FromPort, ToPort   int
	ICMPType, ICMPCode int
}

type ACLRule struct {
	Rule   IPRule
	Number int
	Allow  bool
}

// Policy is derived from authoritative EC2 state, never persisted by a runtime.
// Security rules are unions; ACL rules are ordered and default-deny.
type Policy struct {
	Subnet                          netip.Prefix
	SecurityIngress, SecurityEgress []IPRule
	ACLIngress, ACLEgress           []ACLRule
	// PublicIPv4 is allocated by EC2. PublicEgress additionally requires an
	// active IGW route; neither a route nor assignment alone grants admission.
	PublicIPv4   netip.Addr
	PublicEgress bool
}

// Equal compares the effective ordered packet policy, ignoring slice ownership.
func (p Policy) Equal(other Policy) bool {
	return p.Subnet == other.Subnet && p.PublicIPv4 == other.PublicIPv4 && p.PublicEgress == other.PublicEgress &&
		slices.Equal(p.SecurityIngress, other.SecurityIngress) &&
		slices.Equal(p.SecurityEgress, other.SecurityEgress) &&
		slices.Equal(p.ACLIngress, other.ACLIngress) &&
		slices.Equal(p.ACLEgress, other.ACLEgress)
}
