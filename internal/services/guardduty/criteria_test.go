package guardduty

import (
	api "stackd/internal/awsapi/guardduty"
	"strings"
	"testing"
	"time"
)

func TestFindingCriteriaTypedNestedArrays(t *testing.T) {
	f := api.Finding{Resource: &api.Resource{InstanceDetails: &api.InstanceDetails{NetworkInterfaces: api.NetworkInterfaces{{PrivateIpAddresses: api.PrivateIpAddresses{{PrivateIpAddress: new(api.SensitiveString("10.0.0.1"))}, {PrivateIpAddress: new(api.SensitiveString("10.0.0.2"))}}}}}}}
	key := api.String("resource.instanceDetails.networkInterfaces.privateIpAddresses.privateIpAddress")
	for _, tc := range []struct {
		name string
		c    api.Condition
		want bool
	}{
		{"any nested value", api.Condition{Equals: api.Equals{"10.0.0.2"}}, true},
		{"missing nested value", api.Condition{Eq: api.Eq{"10.0.0.3"}}, false},
		{"negative excludes whole finding", api.Condition{NotEquals: api.NotEquals{"10.0.0.2"}}, false},
		{"negative includes nonmatching array", api.Condition{Neq: api.Neq{"10.0.0.3"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &api.FindingCriteria{Criterion: api.Criterion{key: tc.c}}
			if err := validateCriteria(c); err != nil {
				t.Fatal(err)
			}
			if got := matchesFinding(f, c); got != tc.want {
				t.Fatalf("matched=%v, want %v", got, tc.want)
			}
		})
	}
}
func TestFindingCriteriaTimestampRangesAndAliases(t *testing.T) {
	now := time.Date(2026, 9, 29, 1, 2, 3, 456000000, time.UTC)
	f := api.Finding{CreatedAt: new(api.String(now.Format(time.RFC3339Nano))), Severity: new(api.Double(8)), Service: &api.Service{Archived: new(api.Boolean(false))}}
	c := &api.FindingCriteria{Criterion: api.Criterion{
		"createdAt":        {GreaterThanOrEqual: new(api.Long(now.UnixMilli())), LessThan: new(api.Long(now.UnixMilli() + 1))},
		"severity":         {Gt: new(api.Integer(7)), Lte: new(api.Integer(8))},
		"service.archived": {Equals: api.Equals{"false"}},
	}}
	if err := validateCriteria(c); err != nil {
		t.Fatal(err)
	}
	if !matchesFinding(f, c) {
		t.Fatal("timestamp milliseconds, integer aliases and boolean did not match")
	}
	f.CreatedAt = new(api.String(now.Add(time.Millisecond).Format(time.RFC3339Nano)))
	if matchesFinding(f, c) {
		t.Fatal("exclusive timestamp bound matched")
	}
	f.CreatedAt = nil
	if matchesFinding(f, c) {
		t.Fatal("missing timestamp matched numerical condition")
	}
}
func TestFindingCriteriaWildcardAndUnsupported(t *testing.T) {
	f := api.Finding{Type: new(api.FindingType("Recon:EC2/PortProbeUnprotectedPort"))}
	c := &api.FindingCriteria{Criterion: api.Criterion{"type": {Matches: api.Matches{"Recon:EC?/Port*"}, NotMatches: api.NotMatches{"*DNS*"}}}}
	if err := validateCriteria(c); err != nil {
		t.Fatal(err)
	}
	if !matchesFinding(f, c) {
		t.Fatal("wildcard failed")
	}
	if err := validateQueryCriteria(c); err == nil {
		t.Fatal("query accepted filter-only wildcard operators")
	}
	if wildcardMatch("recon:*", value(f.Type)) {
		t.Fatal("wildcard unexpectedly ignored case")
	}
	if !wildcardMatch("?/*", "é/anything") || wildcardMatch("[ab]", "a") {
		t.Fatal("wildcards must be rune-aware without shell character classes")
	}
	for _, bad := range []*api.FindingCriteria{
		{Criterion: api.Criterion{"unimplemented.path": {Equals: api.Equals{"x"}}}},
		{Criterion: api.Criterion{"severity": {GreaterThan: new(api.Long(0)), Equals: api.Equals{"NaN"}}}},
		{Criterion: api.Criterion{"type": {Gt: new(api.Integer(2))}}},
	} {
		if err := validateCriteria(bad); err == nil {
			t.Fatalf("accepted unsupported criteria: %+v", bad)
		}
	}
}
func TestFindingSortUsesNumericOrderAndStableID(t *testing.T) {
	findings := []api.Finding{{Id: new(api.String("c")), Severity: new(api.Double(2))}, {Id: new(api.String("b")), Severity: new(api.Double(10))}, {Id: new(api.String("a")), Severity: new(api.Double(10))}}
	if err := sortFindings(findings, &api.SortCriteria{AttributeName: new(api.String("severity")), OrderBy: new(api.OrderBy("DESC"))}); err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"a", "b", "c"} {
		if value(findings[i].Id) != id {
			t.Fatalf("position %d = %s, want %s", i, value(findings[i].Id), id)
		}
	}
	if err := sortFindings(findings, &api.SortCriteria{AttributeName: new(api.String("unknown"))}); err == nil {
		t.Fatal("accepted unsupported sort field")
	}
}

func TestFindingCriteriaEmptyPositiveAndOpaqueAdditionalInfo(t *testing.T) {
	f := api.Finding{Type: new(api.FindingType("type")), Service: &api.Service{AdditionalInfo: &api.ServiceAdditionalInfo{Value: new(api.String(`{"sample":true,"inBytes":128,"userAgent":{"fullUserAgent":"sample-agent"}}`))}}}
	c := &api.FindingCriteria{Criterion: api.Criterion{"type": {Equals: api.Equals{}}}}
	if err := validateCriteria(c); err != nil {
		t.Fatal(err)
	}
	if matchesFinding(f, c) {
		t.Fatal("empty positive condition matched")
	}
	c = &api.FindingCriteria{Criterion: api.Criterion{"service.additionalInfo.sample": {Equals: api.Equals{"true"}}, "service.additionalInfo.inBytes": {GreaterThan: new(api.Long(100))}, "service.additionalInfo.userAgent.fullUserAgent": {Equals: api.Equals{"sample-agent"}}}}
	if err := validateCriteria(c); err != nil {
		t.Fatal(err)
	}
	if !matchesFinding(f, c) {
		t.Fatal("opaque AdditionalInfo criteria did not match")
	}
	f.Service.AdditionalInfo.Value = new(api.String(`{"sample":false,"inBytes":128}`))
	if matchesFinding(f, c) {
		t.Fatal("opaque AdditionalInfo mismatch matched")
	}
}

func TestFindingStringRebindingPreservesUnrelatedSampleDetails(t *testing.T) {
	source := api.Finding{AccountId: new(api.String("111111111111")), Region: new(api.String("us-west-2")), Resource: &api.Resource{InstanceDetails: &api.InstanceDetails{NetworkInterfaces: api.NetworkInterfaces{{Ipv6Addresses: api.Ipv6Addresses{"111111111111-resource", "native-address"}}}}}, Service: &api.Service{Action: &api.Action{AwsApiCallAction: &api.AwsApiCallAction{AffectedResources: api.AffectedResources{"resource": "arn:aws:ec2:us-west-2:111111111111:instance/example"}}}}}
	f := api.CloneFinding(source)
	replace := strings.NewReplacer("111111111111", "222222222222")
	mapFindingStrings(&f, replace.Replace)
	if value(f.AccountId) != "222222222222" || f.Service.Action.AwsApiCallAction.AffectedResources["resource"] != "arn:aws:ec2:us-west-2:222222222222:instance/example" {
		t.Fatal("nested scope strings were not rebound")
	}
	ips := f.Resource.InstanceDetails.NetworkInterfaces[0].Ipv6Addresses
	if ips[0] != "222222222222-resource" || ips[1] != "native-address" || value(f.Region) != "us-west-2" {
		t.Fatal("rebinding changed unrelated fictional details")
	}
	if value(source.AccountId) != "111111111111" || source.Resource.InstanceDetails.NetworkInterfaces[0].Ipv6Addresses[0] != "111111111111-resource" {
		t.Fatal("rebinding changed immutable source corpus")
	}
}

func TestFindingDefaultSortAndCursorShareTieBreaking(t *testing.T) {
	rows := []api.Finding{
		{Id: new(api.String("later-id")), Service: &api.Service{EventLastSeen: new(api.String("2026-09-29T01:00:00Z"))}},
		{Id: new(api.String("older")), Service: &api.Service{EventLastSeen: new(api.String("2026-09-28T01:00:00Z"))}},
		{Id: new(api.String("earlier-id")), Service: &api.Service{EventLastSeen: new(api.String("2026-09-29T01:00:00Z"))}},
	}
	if err := sortFindings(rows, nil); err != nil {
		t.Fatal(err)
	}
	if value(rows[0].Id) != "earlier-id" || value(rows[1].Id) != "later-id" || value(rows[2].Id) != "older" {
		t.Fatal("default last-seen ordering or ID tie break is incorrect")
	}
	cursor := rows[0]
	if compareFindings(rows[1], cursor, nil) <= 0 || compareFindings(cursor, cursor, nil) != 0 {
		t.Fatal("cursor comparison diverged from sorting")
	}
	if err := sortFindings(rows, &api.SortCriteria{AttributeName: new(api.String("id"))}); err == nil {
		t.Fatal("native-unsupported explicit ID sort accepted")
	}
}
