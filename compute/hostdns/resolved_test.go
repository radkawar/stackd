package hostdns

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
)

func TestNativeResolvedPropertyDecoding(t *testing.T) {
	fixtures := []struct{ json, signature, want string }{
		{`{"type":"a(iayqs)","data":[[2,[127,0,0,1],5353,""]]}`, "a(iayqs)", `[[2,[127,0,0,1],5353,""]]`},
		{`{"type":"a(sb)","data":[["gateway.example",true]]}`, "a(sb)", `[["gateway.example",true]]`},
		{`{"type":"b","data":false}`, "b", `false`},
	}
	for _, fixture := range fixtures {
		got, err := decodeProperty([]byte(fixture.json), fixture.signature)
		if err != nil || string(got) != fixture.want {
			t.Fatalf("native decode got %s %v, want %s", got, err, fixture.want)
		}
	}
	for _, malformed := range []string{`{"type":"s","data":false}`, `{"type":"b","data":[]}`, `{"type":"b","data":[true,false]}`, `{"type":"b","data":null}`, `not-json`} {
		if _, err := decodeProperty([]byte(malformed), "b"); err == nil {
			t.Fatalf("accepted malformed native data %s", malformed)
		}
	}
}

func TestNativeResolvedMethodReplyDecoding(t *testing.T) {
	for _, fixture := range []struct{ json, signature, want string }{
		{`{"type":"o","data":["/org/freedesktop/resolve1/link/_34"]}`, "o", `"/org/freedesktop/resolve1/link/_34"`},
		{`{"type":"u","data":[1234]}`, "u", `1234`},
	} {
		got, err := decodeMethodReply([]byte(fixture.json), fixture.signature)
		if err != nil || string(got) != fixture.want {
			t.Fatalf("method reply = %s, %v; want %s", got, err, fixture.want)
		}
	}
}

func TestResolvedMethodsPreserveLiteralPortsAndScopedDomains(t *testing.T) {
	c := Config{Address: "127.0.0.1:5353", Domains: []string{"gateway.example", "aws.example"}}
	changes := resolvedAfter(c)
	if len(changes) != 2 || changes[0].Key != "Domains" || changes[1].Key != "DNSEx" {
		t.Fatal("resolver must establish scope before installing DNS servers")
	}
	args, err := resolvedWriteArgs("DNSEx", changes[1].After)
	want := []string{"SetLinkDNSEx", "ia(iayqs)", "1", "2", "4", "127", "0", "0", "1", "5353", ""}
	if err != nil || !reflect.DeepEqual(args, want) {
		t.Fatalf("wrong literal DNS method: %v %v", args, err)
	}
	args, err = resolvedWriteArgs("Domains", changes[0].After)
	want = []string{"SetLinkDomains", "ia(sb)", "2", "gateway.example", "true", "aws.example", "true"}
	if err != nil || !reflect.DeepEqual(args, want) {
		t.Fatalf("wrong routing-only method: %v %v", args, err)
	}
	c.Address = "[::1]:5354"
	args, err = resolvedWriteArgs("DNSEx", resolvedAfter(c)[1].After)
	if err != nil || args[3] != "10" || args[4] != "16" || args[len(args)-2] != "5354" {
		t.Fatalf("IPv6 method: %v %v", args, err)
	}
	for _, bad := range []string{`[[2,[127,0,0],53,""]]`, `[[2,[256,0,0,1],53,""]]`, `[[10,[127,0,0,1],53,""]]`, `[[2,[127,0,0,1],65536,""]]`, `[[2]]`} {
		if _, err := resolvedWriteArgs("DNSEx", json.RawMessage(bad)); err == nil {
			t.Fatalf("accepted native boundary %s", bad)
		}
	}
	for _, key := range []string{"DNSEx", "Domains"} {
		args, err := resolvedWriteArgs(key, json.RawMessage(`[]`))
		if err != nil || args[len(args)-1] != "0" {
			t.Fatalf("exact empty restoration %s: %v %v", key, args, err)
		}
	}
}

func TestExplicitResolvedReceiptCannotClaimPreexistingSettings(t *testing.T) {
	c := Config{Address: "127.0.0.1:53", Domains: []string{"gateway.example"}, Interface: "dedicated"}
	changes := resolvedAfter(c)
	for i := range changes {
		changes[i].Before = encoded([]any{})
	}
	r := receipt{Config: c, Target: "7", Changes: changes}
	b := resolvedBackend{}
	if err := b.validate(r); err != nil {
		t.Fatal(err)
	}
	r.Changes[1].Before = json.RawMessage(`[[2,[192,0,2,1],53,""]]`)
	if err := b.validate(r); err == nil {
		t.Fatal("receipt forged prior native DNS authority")
	}
}

func TestAutomaticLinkOwnershipAndIncarnationBoundaries(t *testing.T) {
	c := Config{Address: "127.0.0.1:53", Domains: []string{"gateway.example"}, StateDirectory: "/private/state"}
	first, err := plannedLink(c)
	if err != nil {
		t.Fatal(err)
	}
	second, err := plannedLink(c)
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != second.Name || len(first.Name) > 15 || first.Alias == second.Alias || first.Address == second.Address {
		t.Fatal("stable name must not become stable ownership incarnation")
	}
	r := receipt{Config: c, Target: first.Name, Changes: automaticChanges(c, first, "192.0.2.1")}
	if err := validateAutomatic(r); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ownedLink){
		func(link *ownedLink) { link.Alias = "stackd-hostdns:public" },
		func(link *ownedLink) { link.Kind = "bridge" },
		func(link *ownedLink) { link.MTU = 9000 },
		func(link *ownedLink) { link.Master = "bridge0" },
		func(link *ownedLink) {
			link.Addresses = append(link.Addresses, json.RawMessage(`{"local":"192.0.2.1"}`))
		},
		func(link *ownedLink) { link.Routes = append(link.Routes, json.RawMessage(`{"dst":"default"}`)) },
	} {
		changed := first
		mutate(&changed)
		r.Changes[0].After = encoded(changed)
		if err := validateAutomatic(r); err == nil {
			t.Fatalf("accepted altered owned-link receipt: %+v", changed)
		}
	}
}

func TestNativeLinkParserSeparatesActivationFromExternalSettings(t *testing.T) {
	fixture := `[{"ifname":"sdns1234567890","ifalias":"stackd-hostdns:12345678901234567890123456789012","address":"02:12:34:56:78:90","mtu":1500,"flags":["BROADCAST","NOARP","UP","LOWER_UP"],"linkinfo":{"info_kind":"dummy"},"promiscuity":0}]`
	link, up, err := parseOwnedLink([]byte(fixture))
	if err != nil || !up || link.Kind != "dummy" || !reflect.DeepEqual(link.Flags, []string{"BROADCAST", "NOARP"}) {
		t.Fatalf("native link parsing: %+v %t %v", link, up, err)
	}
	original := encoded(link)
	changed := bytes.ReplaceAll([]byte(fixture), []byte(`"mtu":1500`), []byte(`"mtu":9000`))
	mutated, _, err := parseOwnedLink(changed)
	if err != nil || bytes.Equal(original, encoded(mutated)) {
		t.Fatal("native MTU mutation invisible")
	}
	changed = bytes.ReplaceAll([]byte(fixture), []byte(`"promiscuity":0`), []byte(`"promiscuity":1`))
	mutated, _, err = parseOwnedLink(changed)
	if err != nil || bytes.Equal(original, encoded(mutated)) {
		t.Fatal("native promiscuity mutation invisible")
	}
	for _, malformed := range []string{`[]`, `[{},{}]`, `not-json`} {
		if _, _, err := parseOwnedLink([]byte(malformed)); err == nil {
			t.Fatalf("accepted malformed native links %s", malformed)
		}
	}
}

func TestDomainOverlapUsesLabelBoundaries(t *testing.T) {
	for _, test := range []struct {
		a, b string
		want bool
	}{
		{"gateway.example", "child.gateway.example", true},
		{"gateway.example", "example", true},
		{"GATEWAY.EXAMPLE.", "gateway.example", true},
		{"gateway.example", "notgateway.example", false},
		{"gateway.example", "gateway.example.net", false},
	} {
		if got := overlaps(test.a, test.b); got != test.want {
			t.Fatalf("overlap %q %q = %t", test.a, test.b, got)
		}
	}
}

func TestLocalDNSAddressDetection(t *testing.T) {
	assigned := []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24"), netip.MustParsePrefix("2001:db8::10/64")}
	for _, test := range []struct {
		address string
		want    bool
	}{
		{"127.0.0.1", true}, {"::1", true}, {"192.0.2.10", true}, {"::ffff:192.0.2.10", true},
		{"192.0.2.11", false}, {"2001:db8::10", true}, {"2001:db8::11", false},
	} {
		if got := localDNSAddress(netip.MustParseAddr(test.address), assigned); got != test.want {
			t.Fatalf("local DNS address %s = %t", test.address, got)
		}
	}
}
