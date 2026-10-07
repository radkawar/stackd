package route53

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	api "stackd/internal/awsapi/route53"
)

// A CloudFormation claim recovers only its own record, never adopts another
// record, survives public UPSERTs and blocks foreign enforced mutations.
func TestCloudFormationRecordOwnership(t *testing.T) {
	s, _ := testService(t)
	ctx := rootContext("111111111111")
	z := createZone(t, s, ctx, "owned.test", "owned")
	mine := WithCloudFormationOwnership(ctx, "claim-a", true, nil)
	other := WithCloudFormationOwnership(ctx, "claim-b", true, nil)
	record := rr("app.owned.test", "A", 60, "192.0.2.1")

	invoke[api.ChangeResourceRecordSetsResponse](t, s, mine, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("CREATE", record)))
	// Recovery of the same incarnation converges the record.
	invoke[api.ChangeResourceRecordSetsResponse](t, s, mine, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("CREATE", rr("app.owned.test", "A", 60, "192.0.2.2"))))
	requireA(t, s, "app.owned.test.", [4]byte{192, 0, 2, 2})
	reject(t, s, other, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("CREATE", record)), "InvalidChangeBatch")
	reject(t, s, other, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("UPSERT", record)), "InvalidChangeBatch")
	reject(t, s, other, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("DELETE", rr("app.owned.test", "A", 60, "192.0.2.2"))), "InvalidChangeBatch")

	// A public UPSERT keeps the retained claim, observed through a listing.
	invoke[api.ChangeResourceRecordSetsResponse](t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("UPSERT", rr("app.owned.test", "A", 60, "192.0.2.3"))))
	rows := map[string]string{}
	invoke[api.ListResourceRecordSetsResponse](t, s, WithCloudFormationOwnership(ctx, "", false, rows), "ListResourceRecordSets", &api.ListResourceRecordSetsRequest{HostedZoneId: z.HostedZone.Id})
	if got := rows[CloudFormationRecordKey("app.owned.test.", "A", "")]; got != "claim-a" {
		t.Fatalf("retained claim = %q", got)
	}

	// Unowned records are never adopted by an enforced claim.
	manual := rr("manual.owned.test", "A", 60, "192.0.2.9")
	invoke[api.ChangeResourceRecordSetsResponse](t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("CREATE", manual)))
	reject(t, s, mine, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("UPSERT", manual)), "InvalidChangeBatch")

	// The owning claim deletes by identity even after value drift.
	invoke[api.ChangeResourceRecordSetsResponse](t, s, mine, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("DELETE", rr("app.owned.test", "A", 60, "192.0.2.1"))))
	if exists, _ := query(t, s, "app.owned.test.", dnsmessage.TypeA); exists {
		t.Fatal("owned record survived deletion")
	}
}
