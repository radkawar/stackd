package guardduty

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func ipListTestRange(first, last string) IPRange {
	low := netip.MustParseAddr(first).As4()
	high := netip.MustParseAddr(last).As4()
	return IPRange{First: binary.BigEndian.Uint32(low[:]), Last: binary.BigEndian.Uint32(high[:])}
}

func ipListTestSTIX(value string) string {
	return `<s:STIX_Package xmlns:s="http://stix.mitre.org/stix-1" xmlns:c="http://cybox.mitre.org/cybox-2" xmlns:a="http://cybox.mitre.org/objects#AddressObject-2"><s:Observables><c:Observable><c:Object><c:Properties category="ipv4-addr">` + value + `</c:Properties></c:Object></c:Observable></s:Observables></s:STIX_Package>`
}

func TestParseIPListDocumentedExamples(t *testing.T) {
	// AWS's STIX example omits the space before condition. Correct that XML
	// typo here; malformed XML is deliberately not accepted by the parser.
	stix := `<?xml version="1.0" encoding="UTF-8"?>
<stix:STIX_Package xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:stix="http://stix.mitre.org/stix-1" xmlns:cybox="http://cybox.mitre.org/cybox-2"
 xmlns:AddressObject="http://cybox.mitre.org/objects#AddressObject-2" version="1.2">
 <stix:Observables cybox_major_version="1" cybox_minor_version="1">
  <cybox:Observable><cybox:Object><cybox:Properties xsi:type="AddressObject:AddressObjectType" category="ipv4-addr">
   <AddressObject:Address_Value condition="InclusiveBetween">192.0.2.0##comma##192.0.2.255</AddressObject:Address_Value>
  </cybox:Properties></cybox:Object></cybox:Observable>
  <cybox:Observable><cybox:Object><cybox:Properties xsi:type="AddressObject:AddressObjectType" category="ipv4-addr">
   <AddressObject:Address_Value>198.51.100.1</AddressObject:Address_Value>
  </cybox:Properties></cybox:Object></cybox:Observable>
  <cybox:Observable><cybox:Object><cybox:Properties xsi:type="AddressObject:AddressObjectType" category="ipv4-addr">
   <AddressObject:Address_Value>203.0.113.1</AddressObject:Address_Value>
  </cybox:Properties></cybox:Object></cybox:Observable>
 </stix:Observables>
</stix:STIX_Package>`
	fireEye := `reportId, title, threatScape, audience, intelligenceType, publishDate, reportLink, webLink, emailIdentifier, senderAddress, senderName, sourceDomain, sourceIp, subject, recipient, emailLanguage, fileName, fileSize, fuzzyHash, fileIdentifier, md5, sha1, sha256, description, fileType, packer, userAgent, registry, fileCompilationDateTime, filePath, asn, cidr, domain, domainTimeOfLookup, networkIdentifier, ip, port, protocol, registrantEmail, registrantName, networkType, url, malwareFamily, malwareFamilyId, actor, actorId, observationTime

01-00000001, Example, Test, Operational, threat, 1494944400, https://www.example.com/report/01-00000001, https://www.example.com/report/01-00000001, , , , , , , , , , , , , , , , , , , , , , , , 192.0.2.0/24, , , Related, , , , , , network, , Ursnif, 21a14673-0d94-46d3-89ab-8281a0466099, , , 1494944400

01-00000002, Example, Test, Operational, threat, 1494944400, https://www.example.com/report/01-00000002, https://www.example.com/report/01-00000002, , , , , , , , , , , , , , , , , , , , , , , , , , , Related, 198.51.100.1, , , , , network, , Ursnif, 12ab7bc4-62ed-49fa-99e3-14b92afc41bf, , ,1494944400

01-00000003, Example, Test, Operational, threat, 1494944400, https://www.example.com/report/01-00000003, https://www.example.com/report/01-00000003, , , , , , , , , , , , , , , , , , , , , , , , , , , Related, 203.0.113.1, , , , , network, , Ursnif, 8a78c3db-7bcb-40bc-a080-75bd35a2572d, , , 1494944400
`
	want := []IPRange{
		ipListTestRange("192.0.2.0", "192.0.2.255"),
		ipListTestRange("198.51.100.1", "198.51.100.1"),
		ipListTestRange("203.0.113.1", "203.0.113.1"),
	}
	for _, tc := range []struct {
		format  string
		content string
		want    []IPRange
	}{
		{"TXT", "192.0.2.0/24\n198.51.100.1\n203.0.113.1\n", want},
		{"STIX", stix, want},
		{"OTX_CSV", "Indicator type, Indicator, Description\nCIDR, 192.0.2.0/24, example\nIPv4, 198.51.100.1, example\nIPv4, 203.0.113.1, example\n", want},
		{"FIRE_EYE", fireEye, want},
		{"PROOF_POINT", "ip, category, score, first_seen, last_seen, ports (|)\n198.51.100.1, 1, 100, 2000-01-01, 2000-01-01, \n203.0.113.1, 1, 100, 2000-01-01, 2000-01-01, 80\n", want[1:]},
		{"ALIEN_VAULT", "198.51.100.1#4#2#Malicious Host#US##0.0,0.0#3\n203.0.113.1#4#2#Malicious Host#US##0.0,0.0#3\n", want[1:]},
	} {
		t.Run(tc.format, func(t *testing.T) {
			got, err := parseIPList(tc.format, []byte(tc.content), 2000)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ranges = %v, error = %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestParseIPListRangesAndMixedFeeds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		format  string
		content string
		want    []IPRange
	}{
		{"merge out of order overlapping adjacent and repeated", "TXT", "192.0.2.255\n192.0.2.128/25\n192.0.2.1\n192.0.2.0/25\n192.0.2.0/24\n192.0.3.0\n192.0.3.2\n", []IPRange{ipListTestRange("192.0.2.0", "192.0.3.0"), ipListTestRange("192.0.3.2", "192.0.3.2")}},
		{"entire IPv4 space", "TXT", "255.255.255.255\n192.0.2.5/0\n0.0.0.0\n", []IPRange{{First: 0, Last: ^uint32(0)}}},
		{"no uint32 wraparound", "TXT", "255.255.255.255\n0.0.0.0\n255.255.255.254/31\n", []IPRange{{First: 0, Last: 0}, {First: ^uint32(0) - 1, Last: ^uint32(0)}}},
		{"private documentation and host bits", "TXT", " 10.0.0.9/30\r\n\r\n 192.0.2.1/32 \r\n", []IPRange{ipListTestRange("10.0.0.8", "10.0.0.11"), ipListTestRange("192.0.2.1", "192.0.2.1")}},
		{"CSV headers reordered and quoting", "OTX_CSV", "Description,Indicator,IndicatorType\n\"contains, commas\",192.0.2.1,IPv4\nother,example.com,Domain name\n", []IPRange{ipListTestRange("192.0.2.1", "192.0.2.1")}},
		{"FireEye selects all IP columns only", "FIRE_EYE", "description,sourceIp,ip,cidr,domain\n203.0.113.9,192.0.2.1,198.51.100.1,203.0.113.7/24,\n,,,,bad.example.com\n", []IPRange{ipListTestRange("192.0.2.1", "192.0.2.1"), ipListTestRange("198.51.100.1", "198.51.100.1"), ipListTestRange("203.0.113.0", "203.0.113.255")}},
		{"ProofPoint header lookup", "PROOF_POINT", "score,ip,ports (|)\n100,192.0.2.1,80\n", []IPRange{ipListTestRange("192.0.2.1", "192.0.2.1")}},
		{"AlienVault mixed indicators", "ALIEN_VAULT", "example.com#4#2\n" + strings.Repeat("a", 64) + "#4#2\n192.0.2.1#4#2\n", []IPRange{ipListTestRange("192.0.2.1", "192.0.2.1")}},
		{"STIX comma interval Equals and default", "STIX", ipListTestSTIX(`<a:Address_Value condition="InclusiveBetween">192.0.2.2, 192.0.2.4</a:Address_Value><a:Address_Value condition="Equals">192.0.2.1</a:Address_Value><a:Address_Value>192.0.2.5</a:Address_Value>`), []IPRange{ipListTestRange("192.0.2.1", "192.0.2.5")}},
		{"STIX ignores arbitrary text", "STIX", ipListTestSTIX(`<a:Description>203.0.113.1</a:Description><a:Address_Value>192.0.2.1/32</a:Address_Value>`), []IPRange{ipListTestRange("192.0.2.1", "192.0.2.1")}},
		{"STIX boundary interval", "STIX", ipListTestSTIX(`<a:Address_Value condition="InclusiveBetween">0.0.0.0##comma##255.255.255.255</a:Address_Value>`), []IPRange{{First: 0, Last: ^uint32(0)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseIPList(tc.format, []byte(tc.content), 2000)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ranges = %v, error = %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestParseIPListRejectsInvalidFeeds(t *testing.T) {
	stixValue := func(value string) string { return ipListTestSTIX(`<a:Address_Value>` + value + `</a:Address_Value>`) }
	for _, tc := range []struct {
		name    string
		format  string
		content string
	}{
		{"unknown format", "CSV", "192.0.2.1"},
		{"empty", "TXT", " \r\n\n"},
		{"IPv6", "TXT", "2001:db8::1"},
		{"mapped IPv6", "TXT", "::ffff:192.0.2.1"},
		{"IPv6 prefix", "TXT", "2001:db8::/32"},
		{"invalid octet", "TXT", "256.0.2.1"},
		{"negative octet", "TXT", "192.0.2.-1"},
		{"leading zero", "TXT", "192.00.2.1"},
		{"invalid prefix", "TXT", "192.0.2.1/33"},
		{"TXT domain", "TXT", "example.com"},
		{"TXT arbitrary tokens", "TXT", "192.0.2.1 198.51.100.1"},
		{"AlienVault missing separator", "ALIEN_VAULT", "192.0.2.1"},
		{"AlienVault invalid numeric address", "ALIEN_VAULT", "999.0.0.1#4#2"},
		{"AlienVault IPv6", "ALIEN_VAULT", "2001:db8::1#4#2"},
		{"AlienVault non-IP only", "ALIEN_VAULT", "example.com#4#2"},
		{"OTX missing type", "OTX_CSV", "Indicator,Description\n192.0.2.1,test\n"},
		{"OTX missing indicator", "OTX_CSV", "IndicatorType,Description\nIPv4,test\n"},
		{"OTX duplicate header", "OTX_CSV", "IndicatorType,Indicator,Indicator\nIPv4,192.0.2.1,192.0.2.2\n"},
		{"OTX empty type", "OTX_CSV", "IndicatorType,Indicator\n,192.0.2.1\n"},
		{"OTX empty IP", "OTX_CSV", "IndicatorType,Indicator\nIPv4,\n"},
		{"OTX explicit IPv6", "OTX_CSV", "IndicatorType,Indicator\nIPv4,192.0.2.1\nIPv6,2001:db8::1\n"},
		{"OTX mislabeled IPv6", "OTX_CSV", "IndicatorType,Indicator\nIPv4,2001:db8::1\n"},
		{"OTX non-IP only", "OTX_CSV", "IndicatorType,Indicator\nDomain name,example.com\n"},
		{"CSV malformed quotes", "OTX_CSV", "IndicatorType,Indicator\nIPv4,\"192.0.2.1\n"},
		{"CSV uneven fields", "OTX_CSV", "IndicatorType,Indicator\nIPv4,192.0.2.1,extra\n"},
		{"ProofPoint missing header", "PROOF_POINT", "domain,score\n192.0.2.1,100\n"},
		{"ProofPoint domain in IP column", "PROOF_POINT", "ip,score\nexample.com,100\n"},
		{"FireEye missing headers", "FIRE_EYE", "description,domain\n192.0.2.1,example.com\n"},
		{"FireEye non-IP only", "FIRE_EYE", "ip,domain\n,example.com\n"},
		{"FireEye bad populated IP", "FIRE_EYE", "ip,cidr\ninvalid,192.0.2.0/24\n"},
		{"STIX arbitrary tag", "STIX", ipListTestSTIX(`<a:Description>192.0.2.1</a:Description>`)},
		{"STIX bogus namespace", "STIX", strings.Replace(stixValue("192.0.2.1"), ipListAddressNamespace, "https://bogus.example/address", 1)},
		{"STIX unqualified address", "STIX", ipListTestSTIX(`<Address_Value>192.0.2.1</Address_Value>`)},
		{"STIX wrong parent namespace", "STIX", strings.Replace(stixValue("192.0.2.1"), ipListCyboxNamespace, "https://bogus.example/cybox", 1)},
		{"STIX wrong package namespace", "STIX", strings.Replace(stixValue("192.0.2.1"), ipListSTIXNamespace, "https://bogus.example/stix", 1)},
		{"STIX address outside properties", "STIX", `<s:STIX_Package xmlns:s="http://stix.mitre.org/stix-1" xmlns:a="http://cybox.mitre.org/objects#AddressObject-2"><a:Address_Value>192.0.2.1</a:Address_Value></s:STIX_Package>`},
		{"STIX bad XML", "STIX", `<stix:STIX_Package`},
		{"STIX trailing garbage", "STIX", stixValue("192.0.2.1") + "garbage"},
		{"STIX multiple roots", "STIX", stixValue("192.0.2.1") + stixValue("192.0.2.2")},
		{"STIX IPv6", "STIX", stixValue("2001:db8::1")},
		{"STIX false IPv4 category", "STIX", strings.Replace(stixValue("192.0.2.1"), "ipv4-addr", "ipv6-addr", 1)},
		{"STIX unsupported condition", "STIX", ipListTestSTIX(`<a:Address_Value condition="DoesNotEqual">192.0.2.1</a:Address_Value>`)},
		{"STIX qualified condition", "STIX", ipListTestSTIX(`<a:Address_Value a:condition="Equals">192.0.2.1</a:Address_Value>`)},
		{"STIX nested address markup", "STIX", stixValue(`<a:Value>192.0.2.1</a:Value>`)},
		{"STIX reversed endpoints", "STIX", ipListTestSTIX(`<a:Address_Value condition="InclusiveBetween">192.0.2.10,192.0.2.1</a:Address_Value>`)},
		{"STIX missing endpoint", "STIX", ipListTestSTIX(`<a:Address_Value condition="InclusiveBetween">192.0.2.1</a:Address_Value>`)},
		{"STIX invalid numeric endpoint", "STIX", ipListTestSTIX(`<a:Address_Value condition="InclusiveBetween">192.0.2.1,4294967295</a:Address_Value>`)},
		{"STIX too many endpoints", "STIX", ipListTestSTIX(`<a:Address_Value condition="InclusiveBetween">192.0.2.1,192.0.2.2,192.0.2.3</a:Address_Value>`)},
		{"STIX CIDR endpoint", "STIX", ipListTestSTIX(`<a:Address_Value condition="InclusiveBetween">192.0.2.0/24,192.0.2.255</a:Address_Value>`)},
		{"STIX DTD", "STIX", `<!DOCTYPE STIX_Package SYSTEM "file:///etc/passwd">` + stixValue("192.0.2.1")},
		{"STIX entity expansion", "STIX", `<!DOCTYPE STIX_Package [<!ENTITY ip "192.0.2.1">]>` + stixValue("&ip;")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := parseIPList(tc.format, []byte(tc.content), 2000); err == nil || got != nil {
				t.Fatalf("invalid feed returned ranges %v and error %v", got, err)
			}
		})
	}
}

func TestParseIPListLimitsBeforeCoalescing(t *testing.T) {
	for _, limit := range []int{2000, 250000} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			row := []byte("192.0.2.1\n")
			content := bytes.Repeat(row, limit)
			want := []IPRange{ipListTestRange("192.0.2.1", "192.0.2.1")}
			got, err := parseIPList("TXT", content, limit)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("at quota: ranges %v, error %v; want %v", got, err, want)
			}
			if _, err := parseIPList("TXT", append(content, row...), limit); err == nil {
				t.Fatal("duplicate rows bypassed entry quota")
			}
		})
	}
	for _, tc := range []struct {
		format  string
		content string
	}{
		{"FIRE_EYE", "sourceIp,ip,cidr\n192.0.2.1,192.0.2.1,192.0.2.0/24\n"},
		{"STIX", ipListTestSTIX(`<a:Address_Value>192.0.2.1</a:Address_Value><a:Address_Value>192.0.2.1</a:Address_Value>`)},
		{"OTX_CSV", "IndicatorType,Indicator\nIPv4,192.0.2.1\nIPv4,192.0.2.1\n"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			if _, err := parseIPList(tc.format, []byte(tc.content), 1); err == nil {
				t.Fatal("multiple extracted entries bypassed quota")
			}
		})
	}
	if _, err := parseIPList("TXT", []byte("192.0.2.1"), 0); err == nil {
		t.Fatal("accepted zero entry quota")
	}
	oversize := bytes.Repeat([]byte(" "), ipListMaxBytes+1)
	copy(oversize, "192.0.2.1\n")
	if got, err := parseIPList("TXT", oversize, 2000); err == nil || got != nil {
		t.Fatalf("oversized feed returned ranges %v and error %v", got, err)
	}
}
