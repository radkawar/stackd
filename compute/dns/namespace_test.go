package dns

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsQuestion(t *testing.T, name string, kind dnsmessage.Type) dnsmessage.Question {
	t.Helper()
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	return dnsmessage.Question{Name: qname, Type: kind, Class: dnsmessage.ClassINET}
}

func TestNamespaceBoundariesAndHonestRecordFamilies(t *testing.T) {
	addresses := []netip.Addr{
		netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("2001:db8::7"),
		netip.MustParseAddr("::ffff:192.0.2.7"),
	}
	resolver, err := NewNamespace("Gateway.Example.", addresses)
	if err != nil {
		t.Fatal(err)
	}
	addresses[0] = netip.MustParseAddr("192.0.2.99")
	for _, name := range []string{"gateway.example.", "a.b.GATEWAY.EXAMPLE."} {
		for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeTXT, dnsmessage.TypeALL} {
			result, err := resolver.LookupDNS(t.Context(), dnsQuestion(t, name, kind))
			if err != nil || !result.Authoritative || !result.Exists || result.Referral {
				t.Fatalf("%s %s: result=%+v error=%v", name, kind, result, err)
			}
			switch kind {
			case dnsmessage.TypeA:
				if len(result.Answers) != 1 || result.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 7} {
					t.Fatalf("A addresses copied, fabricated, or duplicated: %+v", result)
				}
			case dnsmessage.TypeAAAA:
				if len(result.Answers) != 1 || result.Answers[0].Body.(*dnsmessage.AAAAResource).AAAA != netip.MustParseAddr("2001:db8::7").As16() {
					t.Fatalf("AAAA addresses: %+v", result)
				}
			default:
				if len(result.Answers) != 0 {
					t.Fatalf("invented non-address records: %+v", result)
				}
			}
		}
	}
	for _, name := range []string{"notgateway.example.", "gateway.example.attacker.", "example.", "."} {
		result, err := resolver.LookupDNS(t.Context(), dnsQuestion(t, name, dnsmessage.TypeA))
		if err != nil || result.Authoritative || result.Exists || len(result.Answers) != 0 {
			t.Fatalf("namespace escaped to %s: %+v %v", name, result, err)
		}
	}
	for _, addresses := range [][]netip.Addr{nil, {netip.MustParseAddr("192.0.2.8")}} {
		resolver, err := NewNamespace("gateway.example", addresses)
		if err != nil {
			t.Fatal(err)
		}
		result, err := resolver.LookupDNS(t.Context(), dnsQuestion(t, "gateway.example.", dnsmessage.TypeAAAA))
		if err != nil || !result.Authoritative || !result.Exists || len(result.Answers) != 0 {
			t.Fatalf("absent family should be NODATA: %+v %v", result, err)
		}
	}
}

func TestNamespaceRejectsInvalidAuthorityAndAddresses(t *testing.T) {
	for _, domain := range []string{"", ".", " example.test", "example.test ", "a..test", "a.test..", "*.test", "_service.test", "https://example.test", "-a.test", "a-.test", "127.0.0.1", "::1", "é.test", "K.example", strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 127) + "a"} {
		if _, err := NewNamespace(domain, nil); err == nil {
			t.Errorf("invalid namespace accepted: %q", domain)
		}
	}
	for _, address := range []netip.Addr{{}, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::"), netip.MustParseAddr("224.0.0.1"), netip.MustParseAddr("ff02::1"), netip.MustParseAddr("fe80::1%eth0"), netip.MustParseAddr("255.255.255.255")} {
		if _, err := NewNamespace("gateway.example", []netip.Addr{address}); err == nil {
			t.Errorf("unusable namespace address accepted: %v", address)
		}
	}
}

func TestRedirectRequiresRealPeerAndExplicitImmutableACL(t *testing.T) {
	address := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	if _, err := NewRedirect("aws.example", address, nil); err == nil {
		t.Fatal("redirect without an ACL accepted")
	}
	if _, err := NewRedirect("aws.example", address, []netip.Prefix{{}}); err == nil {
		t.Fatal("invalid redirect ACL accepted")
	}
	clients := []netip.Prefix{netip.MustParsePrefix("::ffff:192.0.2.4/128")}
	resolver, err := NewRedirect("aws.example", address, clients)
	if err != nil {
		t.Fatal(err)
	}
	clients[0] = netip.MustParsePrefix("0.0.0.0/0")
	question := dnsQuestion(t, "sqs.region.aws.example.", dnsmessage.TypeA)
	for _, ctx := range []context.Context{t.Context(), withPeerAddress(t.Context(), netip.MustParseAddr("192.0.2.5"))} {
		result, err := resolver.LookupDNS(ctx, question)
		if err != nil || result.Authoritative || result.Exists || len(result.Answers) != 0 {
			t.Fatalf("denied peer received redirect: %+v %v", result, err)
		}
	}
	result, err := resolver.LookupDNS(withPeerAddress(t.Context(), netip.MustParseAddr("::ffff:192.0.2.4")), question)
	if err != nil || !result.Authoritative || !result.Exists || len(result.Answers) != 1 {
		t.Fatalf("allowed mapped peer lost redirect: %+v %v", result, err)
	}
	if _, ok := PeerAddress(t.Context()); ok {
		t.Fatal("direct context invented a peer")
	}
}

func TestNamespaceDNSCaseFoldingIsASCIIOnly(t *testing.T) {
	resolver, err := NewNamespace("k.example", []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"K.example.", "child.K.example."} {
		result, err := resolver.LookupDNS(t.Context(), dnsQuestion(t, name, dnsmessage.TypeA))
		if err != nil || result.Authoritative || len(result.Answers) != 0 {
			t.Fatalf("Unicode-equivalent name entered ASCII namespace: %s %+v %v", name, result, err)
		}
	}
	result, err := resolver.LookupDNS(t.Context(), dnsQuestion(t, "K.EXAMPLE.", dnsmessage.TypeA))
	if err != nil || !result.Authoritative || len(result.Answers) != 1 {
		t.Fatalf("ASCII-equivalent name lost namespace: %+v %v", result, err)
	}
}
