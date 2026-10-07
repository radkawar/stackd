package elbv2

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"stackd/compute/dns"
	"stackd/compute/network"
	api "stackd/internal/awsapi/elbv2"
)

func TestDNSNameUsesNativeALBZone(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/elbv2/alb_native_success.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Account, Region string
		Cases           []struct {
			Action string
			Output api.CreateLoadBalancerOutput
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, observed := range fixture.Cases {
		if observed.Action != "create-load-balancer" {
			continue
		}
		native := observed.Output.LoadBalancers[0]
		lb := LoadBalancerRecord{Scope: Scope{"aws", fixture.Account, fixture.Region}, Data: native}
		_, nativeZone, ok := strings.Cut(value(native.DNSName), ".")
		if !ok {
			t.Fatal("native fixture DNSName has no zone")
		}
		generated := loadBalancerDNSName(lb)
		_, localZone, ok := strings.Cut(generated, ".")
		if !ok || localZone != nativeZone {
			t.Fatalf("ALB name %q does not use native zone %q", generated, nativeZone)
		}
		return
	}
	t.Fatal("native fixture has no CreateLoadBalancer observation")
}

type dnsNetwork struct {
	NetworkAuthority
	attachments map[string]NetworkAttachment
	scopes      map[string]Scope
}

func (n *dnsNetwork) Observe(_ context.Context, sc Scope, owner, id string) (NetworkAttachment, error) {
	attachment, ok := n.attachments[owner+"/"+id]
	if !ok || n.scopes[owner] != sc {
		return NetworkAttachment{}, ErrNotFound
	}
	return attachment, nil
}
func dnsRecord(sc Scope, vpc, scheme string) LoadBalancerRecord {
	lb := LoadBalancerRecord{Scope: sc, AttachmentIDs: map[string]string{"subnet-a": "eni-a", "subnet-b": "eni-b"}, NextReconcile: time.Now().Add(time.Hour)}
	text(&lb.Data.LoadBalancerArn, arn(sc, "loadbalancer/app/same-name/0000000000000001"))
	text(&lb.Data.LoadBalancerName, "same-name")
	text(&lb.Data.Scheme, scheme)
	text(&lb.Data.VpcId, vpc)
	lb.Data.AvailabilityZones = api.AvailabilityZones{{SubnetId: new(api.SubnetId("subnet-a"))}, {SubnetId: new(api.SubnetId("subnet-b"))}}
	return lb
}
func putDNSRecord(t *testing.T, s *Service, lb LoadBalancerRecord) {
	t.Helper()
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.PutLoadBalancer(lb) }); err != nil {
		t.Fatal(err)
	}
}
func dnsLookup(t *testing.T, s *Service, name string, typ dnsmessage.Type) dns.Result {
	t.Helper()
	qname, err := dnsmessage.NewName(strings.ToUpper(name) + ".")
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.LookupDNS(t.Context(), dnsmessage.Question{Name: qname, Type: typ, Class: dnsmessage.ClassINET})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func dnsAddresses(out dns.Result) []string {
	var addresses []string
	for _, record := range out.Answers {
		addresses = append(addresses, netip.AddrFrom4(record.Body.(*dnsmessage.AResource).A).String())
	}
	slices.Sort(addresses)
	return addresses
}
func TestDNSCurrentOwnershipScopeAndWithdrawal(t *testing.T) {
	sc := Scope{"aws", "111111111111", "us-east-1"}
	lb := dnsRecord(sc, "vpc-first", "internal")
	ensureDNSName(&lb)
	name := value(lb.Data.DNSName)
	other := dnsRecord(Scope{"aws", "222222222222", "us-east-1"}, "vpc-second", "internet-facing")
	ensureDNSName(&other)
	networks := &dnsNetwork{attachments: map[string]NetworkAttachment{}, scopes: map[string]Scope{}}
	for i, row := range []LoadBalancerRecord{lb, other} {
		owner := value(row.Data.LoadBalancerArn)
		networks.scopes[owner] = row.Scope
		for j, id := range []string{"eni-a", "eni-b"} {
			networks.attachments[owner+"/"+id] = NetworkAttachment{ID: id, Network: network.Specification{Address: netip.AddrFrom4([4]byte{10, 0, byte(i), byte(j + 4)})}, PublicAddress: netip.AddrFrom4([4]byte{198, 51, byte(i), byte(j + 4)}).String()}
		}
	}
	s := New(Config{Networks: networks})
	defer s.Close()
	putDNSRecord(t, s, lb)
	putDNSRecord(t, s, other)
	if got := dnsAddresses(dnsLookup(t, s, name, dnsmessage.TypeA)); !reflect.DeepEqual(got, []string{"10.0.0.4", "10.0.0.5"}) {
		t.Fatal(got)
	}
	if got := dnsAddresses(dnsLookup(t, s, value(other.Data.DNSName), dnsmessage.TypeA)); !reflect.DeepEqual(got, []string{"198.51.1.4", "198.51.1.5"}) {
		t.Fatal(got)
	}
	alias, err := s.LookupDNSAlias(t.Context(), "dualstack."+name, value(lb.Data.CanonicalHostedZoneId), dnsmessage.TypeA)
	if err != nil || !reflect.DeepEqual(dnsAddresses(dns.Result{Answers: alias}), []string{"10.0.0.4", "10.0.0.5"}) {
		t.Fatalf("ALB alias: %v, %v", alias, err)
	}
	for _, zone := range []string{"", "ZNOTTHEALBZONE"} {
		if err := s.ValidateDNSAlias(t.Context(), name, zone, dnsmessage.TypeA); err == nil {
			t.Fatalf("accepted unrelated hosted zone %q", zone)
		}
	}
	if err := s.ValidateDNSAlias(t.Context(), name, value(lb.Data.CanonicalHostedZoneId), dnsmessage.TypeAAAA); err == nil {
		t.Fatal("accepted IPv6 alias for IPv4-only ALB")
	}
	if out := dnsLookup(t, s, name, dnsmessage.TypeAAAA); !out.Exists || len(out.Answers) != 0 {
		t.Fatal(out)
	}
	// The same attachment's authoritative current address changes independently
	// of reconciliation; no cached DNS address or DNS name may survive it.
	key := value(lb.Data.LoadBalancerArn) + "/eni-a"
	attachment := networks.attachments[key]
	attachment.Network.Address = netip.MustParseAddr("10.0.0.9")
	networks.attachments[key] = attachment
	lb.Data.AvailabilityZones = lb.Data.AvailabilityZones[:1]
	putDNSRecord(t, s, lb)
	if got := dnsAddresses(dnsLookup(t, s, name, dnsmessage.TypeA)); !reflect.DeepEqual(got, []string{"10.0.0.9"}) {
		t.Fatal(got)
	}
	delete(networks.attachments, key)
	if out := dnsLookup(t, s, name, dnsmessage.TypeA); !out.Exists || len(out.Answers) != 0 {
		t.Fatal(out)
	}
	lb.Deleting = true
	putDNSRecord(t, s, lb)
	if out := dnsLookup(t, s, name, dnsmessage.TypeA); out.Exists || len(out.Answers) != 0 {
		t.Fatal(out)
	}
	if err := s.ValidateDNSAlias(t.Context(), name, value(lb.Data.CanonicalHostedZoneId), dnsmessage.TypeA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted ALB accepted as alias: %v", err)
	}
	if got := dnsAddresses(dnsLookup(t, s, value(other.Data.DNSName), dnsmessage.TypeA)); !reflect.DeepEqual(got, []string{"198.51.1.4", "198.51.1.5"}) {
		t.Fatal(got)
	}
	independent := dnsRecord(sc, "vpc-independent-store", "internal")
	ensureDNSName(&independent)
	if value(independent.Data.DNSName) == name || value(other.Data.DNSName) == name {
		t.Fatal("scope/store identity collision")
	}
	if out := dnsLookup(t, s, value(independent.Data.DNSName), dnsmessage.TypeA); out.Exists {
		t.Fatal("foreign store resolved")
	}
}

func TestDNSLegacyMigrationAndServiceReopen(t *testing.T) {
	endpoint, err := dns.Listen(dns.Config{Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	repository := NewMemoryRepository(nil)
	sc := Scope{"aws", "111111111111", "us-east-1"}
	lb := dnsRecord(sc, "vpc-retained", "internal")
	text(&lb.Data.DNSName, "10.0.0.4")
	owner := value(lb.Data.LoadBalancerArn)
	networks := &dnsNetwork{attachments: map[string]NetworkAttachment{owner + "/eni-a": {ID: "eni-a", Network: network.Specification{Address: netip.MustParseAddr("10.0.0.4")}}}, scopes: map[string]Scope{owner: sc}}
	s := New(Config{Repository: repository, Networks: networks, DNS: endpoint})
	putDNSRecord(t, s, lb)
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	name := loadBalancerDNSName(lb)
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, protocol, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, protocol, endpoint.Address())
	}}
	lookup := func() {
		t.Helper()
		addresses, err := resolver.LookupNetIP(t.Context(), "ip4", name+".")
		if err != nil || !reflect.DeepEqual(addresses, []netip.Addr{netip.MustParseAddr("10.0.0.4")}) {
			t.Fatalf("%v %v", addresses, err)
		}
	}
	lookup()
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = New(Config{Repository: repository, Networks: networks, DNS: endpoint})
	defer s.Close()
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	lookup()
	if err = repository.View(t.Context(), func(tx Reader) error {
		row, err := tx.LoadBalancer(sc, owner)
		if err == nil && value(row.Data.DNSName) != name {
			t.Fatal("name changed on reopen")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDNSIndependentEndpoints(t *testing.T) {
	var names []string
	var resolvers []*net.Resolver
	for _, vpc := range []string{"vpc-store-a", "vpc-store-b"} {
		endpoint, err := dns.Listen(dns.Config{Address: "127.0.0.1:0"})
		if err != nil {
			t.Fatal(err)
		}
		defer endpoint.Close()
		lb := dnsRecord(Scope{"aws", "111111111111", "us-east-1"}, vpc, "internal")
		ensureDNSName(&lb)
		owner := value(lb.Data.LoadBalancerArn)
		networks := &dnsNetwork{attachments: map[string]NetworkAttachment{owner + "/eni-a": {ID: "eni-a", Network: network.Specification{Address: netip.MustParseAddr("10.0.0.4")}}}, scopes: map[string]Scope{owner: lb.Scope}}
		s := New(Config{Networks: networks, DNS: endpoint})
		defer s.Close()
		putDNSRecord(t, s, lb)
		if err := s.Start(); err != nil {
			t.Fatal(err)
		}
		names = append(names, value(lb.Data.DNSName))
		resolvers = append(resolvers, &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, protocol, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, protocol, endpoint.Address())
		}})
	}
	for i, resolver := range resolvers {
		addresses, err := resolver.LookupNetIP(t.Context(), "ip4", names[i]+".")
		if err != nil || !reflect.DeepEqual(addresses, []netip.Addr{netip.MustParseAddr("10.0.0.4")}) {
			t.Fatalf("own name: %v %v", addresses, err)
		}
		_, err = resolver.LookupNetIP(t.Context(), "ip4", names[1-i]+".")
		var rejected *net.DNSError
		if !errors.As(err, &rejected) || !rejected.IsNotFound {
			t.Fatalf("foreign store name did not return NXDOMAIN: %v", err)
		}
	}
}
