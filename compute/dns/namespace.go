package dns

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

type peerAddressKey struct{}

// PeerAddress returns the real UDP/TCP client's address, without its source
// port. It is absent for direct resolver calls not made by the DNS endpoint.
func PeerAddress(ctx context.Context) (netip.Addr, bool) {
	address, ok := ctx.Value(peerAddressKey{}).(netip.Addr)
	return address, ok && address.IsValid()
}

func withPeerAddress(ctx context.Context, address netip.Addr) context.Context {
	return context.WithValue(ctx, peerAddressKey{}, address.Unmap())
}

type namespace struct {
	domain   string
	ipv4     [][4]byte
	ipv6     [][16]byte
	clients  []netip.Prefix
	redirect bool
}

// NewNamespace serves the exact domain and its subdomains using only the
// supplied addresses. Missing address families and other record types return
// authoritative NODATA, including when addresses is empty. Native registered
// service owners take precedence over this generic namespace.
func NewNamespace(domain string, addresses []netip.Addr) (Resolver, error) {
	return newNamespace(domain, addresses)
}

// NewRedirect is a namespace visible only to explicitly allowed client
// prefixes. It requires a nonempty ACL; callers without a real serving peer
// never receive a redirect. Denied clients leave resolution to ordinary owners
// or the separately configured forwarding policy.
func NewRedirect(domain string, addresses []netip.Addr, clients []netip.Prefix) (Resolver, error) {
	if len(clients) == 0 {
		return nil, errors.New("DNS redirect requires explicit allowed clients")
	}
	prefixes, err := clientPrefixes(clients)
	if err != nil {
		return nil, err
	}
	n, err := newNamespace(domain, addresses)
	if err != nil {
		return nil, err
	}
	n.redirect, n.clients = true, prefixes
	return n, nil
}

func newNamespace(domain string, addresses []netip.Addr) (*namespace, error) {
	domain = strings.TrimSuffix(domain, ".")
	if len(domain) == 0 || len(domain) > 253 {
		return nil, errors.New("DNS namespace requires a non-root hostname domain")
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return nil, errors.New("DNS namespace cannot be an IP address")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, errors.New("DNS namespace contains an invalid hostname label")
		}
		for _, character := range label {
			if !('a' <= character && character <= 'z' || 'A' <= character && character <= 'Z' || '0' <= character && character <= '9' || character == '-') {
				return nil, errors.New("DNS namespace contains an invalid hostname character")
			}
		}
	}
	n := &namespace{domain: strings.ToLower(domain) + "."}
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !usableAddress(address) {
			return nil, errors.New("DNS namespace requires explicit unicast addresses")
		}
		address = address.Unmap()
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		if address.Is4() {
			n.ipv4 = append(n.ipv4, address.As4())
		} else {
			n.ipv6 = append(n.ipv6, address.As16())
		}
	}
	return n, nil
}

func (n *namespace) LookupDNS(ctx context.Context, question dnsmessage.Question) (Result, error) {
	if question.Class != dnsmessage.ClassINET {
		return Result{}, nil
	}
	name := question.Name.String()
	if !equalDNSName(name, n.domain) {
		start := len(name) - len(n.domain)
		if start <= 0 || name[start-1] != '.' || !equalDNSName(name[start:], n.domain) {
			return Result{}, nil
		}
	}
	if n.redirect {
		peer, ok := PeerAddress(ctx)
		if !ok || !allowsClient(n.clients, peer, false) {
			return Result{}, nil
		}
	}
	result := Result{Authoritative: true, Exists: true}
	header := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, Type: question.Type, TTL: 60}
	switch question.Type {
	case dnsmessage.TypeA:
		result.Answers = make([]dnsmessage.Resource, len(n.ipv4))
		for i, address := range n.ipv4 {
			result.Answers[i] = dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: address}}
		}
	case dnsmessage.TypeAAAA:
		result.Answers = make([]dnsmessage.Resource, len(n.ipv6))
		for i, address := range n.ipv6 {
			result.Answers[i] = dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: address}}
		}
	}
	return result, nil
}

func usableAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	return address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast()
}

func clientPrefixes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, len(prefixes))
	for i, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, errors.New("DNS client ACL contains an invalid prefix")
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, errors.New("DNS IPv4-mapped client prefix must have at least 96 bits")
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		out[i] = prefix.Masked()
	}
	return out, nil
}

func allowsClient(prefixes []netip.Prefix, address netip.Addr, loopbackDefault bool) bool {
	address = address.Unmap()
	if len(prefixes) == 0 {
		return loopbackDefault && address.IsLoopback()
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
