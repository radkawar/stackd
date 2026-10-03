package route53

import (
	"encoding/json"
	"os"
	api "stackd/internal/awsapi/route53"
	"testing"
)

func TestNativeHostedZoneAndMultivalueConstraints(t *testing.T) {
	data, e := os.ReadFile("testdata/native-controls.json")
	if e != nil {
		t.Fatal(e)
	}
	// Decode only the behavioral facts used below; retained capture separately records interrupted capture and exact cleanup.
	var raw struct {
		Observations []struct {
			Label     string `json:"label"`
			ErrorCode string `json:"error_code"`
		}
	}
	if e = json.Unmarshal(data, &raw); e != nil {
		t.Fatal(e)
	}
	codes := map[string]string{}
	for _, row := range raw.Observations {
		codes[row.Label] = row.ErrorCode
	}
	s, _ := testService(t)
	ctx := rootContext("111111111111")
	z := createZone(t, s, ctx, "native.test", "native-reference")
	reject(t, s, ctx, "CreateHostedZone", &api.CreateHostedZoneRequest{Name: new(api.DNSName("native.test")), CallerReference: new(api.Nonce("native-reference"))}, codes["duplicate_same_reference_same_name"])
	listed := invoke[api.ListResourceRecordSetsResponse](t, s, ctx, "ListResourceRecordSets", &api.ListResourceRecordSetsRequest{HostedZoneId: z.HostedZone.Id})
	for _, r := range listed.ResourceRecordSets {
		label := "delete_apex_ns"
		if value(r.Type) == "SOA" {
			label = "delete_apex_soa"
		}
		reject(t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("DELETE", &r)), codes[label])
	}
	multi := rr("multi.native.test", "A", 60, "192.0.2.1", "192.0.2.2")
	multi.MultiValueAnswer = new(api.ResourceRecordSetMultiValueAnswer(true))
	multi.SetIdentifier = new(api.ResourceRecordSetIdentifier("multivalue"))
	reject(t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("CREATE", multi)), codes["multivalue_two_addresses"])
	cname := rr("alias.native.test", "CNAME", 60, "TARGET.EXAMPLE.TEST")
	invoke[api.ChangeResourceRecordSetsResponse](t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("CREATE", cname)))
	invoke[api.ChangeResourceRecordSetsResponse](t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("DELETE", rr("ALIAS.NATIVE.TEST.", "CNAME", 60, "target.example.test."))))
}
