package dns

import (
	"context"
	"errors"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestValidationCNAMEUsesMatchingOwnerAndTCP(t *testing.T) {
	server, err := Listen(Config{Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClient(server.Address())
	if err != nil {
		t.Fatal(err)
	}
	name, _ := dnsmessage.NewName("_token.example.test.")
	target, _ := dnsmessage.NewName("_proof.acm-validations.aws.")
	unrelated, _ := dnsmessage.NewName("_other.example.test.")
	release, err := server.Register(resolverFunc(func(_ context.Context, _ dnsmessage.Question) (Result, error) {
		result := Result{Authoritative: true, Exists: true}
		result.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: target}}}
		// An authoritative section larger than UDP's ceiling forces the client
		// to repeat the same question over TCP, not silently lose the CNAME.
		for range 12 {
			result.Authorities = append(result.Authorities, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.TXTResource{TXT: []string{"a deliberately long authority record that requires TCP fallback"}}})
		}
		return result, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.LookupCNAME(t.Context(), "_TOKEN.EXAMPLE.TEST")
	if err != nil || got != target.String() {
		t.Fatalf("CNAME target=%q error=%v", got, err)
	}
	_, err = client.LookupCNAME(t.Context(), unrelated.String())
	var missing *net.DNSError
	if !errors.As(err, &missing) || !missing.IsNotFound {
		t.Fatalf("unrelated CNAME accepted: %v", err)
	}
	release()
	_, err = client.LookupCNAME(t.Context(), name.String())
	if !errors.As(err, &missing) || !missing.IsNotFound {
		t.Fatalf("withdrawn owner still validated: %v", err)
	}
}

func TestNegativeAuthorityAndDelegationSections(t *testing.T) {
	server, err := Listen(Config{Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	zone, _ := dnsmessage.NewName("example.test.")
	ns, _ := dnsmessage.NewName("ns.example.test.")
	_, err = server.Register(resolverFunc(func(_ context.Context, q dnsmessage.Question) (Result, error) {
		if q.Name.String() == "delegated.example.test." {
			return Result{Referral: true, Authorities: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.NSResource{NS: ns}}}, Additionals: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: ns, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}}, nil
		}
		return Result{Authoritative: true, Authorities: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: zone, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.SOAResource{NS: ns, MBox: ns, Serial: 1, Refresh: 60, Retry: 30, Expire: 3600, MinTTL: 300}}}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"udp", "tcp"} {
		negative := exchange(t, server, protocol, "missing.example.test.", dnsmessage.TypeA)
		if negative.RCode != dnsmessage.RCodeNameError || !negative.Authoritative || len(negative.Authorities) != 1 || negative.Authorities[0].Header.Type != dnsmessage.TypeSOA {
			t.Fatalf("negative response: %+v", negative)
		}
		referral := exchange(t, server, protocol, "delegated.example.test.", dnsmessage.TypeA)
		if referral.RCode != dnsmessage.RCodeSuccess || referral.Authoritative || len(referral.Authorities) != 1 || referral.Authorities[0].Header.Type != dnsmessage.TypeNS || len(referral.Additionals) != 1 {
			t.Fatalf("delegation response: %+v", referral)
		}
	}
}
