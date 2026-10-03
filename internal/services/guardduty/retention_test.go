package guardduty

import (
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/guardduty"
)

func TestRetentionAPIVisibilityBeforeSweep(t *testing.T) {
	s, ctx, detector, _ := filterFixture(t)
	t.Cleanup(func() { _ = s.Close() })
	manual := s.clock.(*clock.Manual)
	now := manual.Now()
	old := Finding{Scope: detector.Scope, DetectorID: detector.ID, ID: "expired", Created: now.Add(-findingRetention + time.Hour), Updated: now, Count: 2, Feedback: "USEFUL", Observation: Observation{Type: "Policy:IAMUser/RootCredentialUsage", Severity: 2}}
	young := old
	young.ID, young.Created = "retained", now
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutFinding(old); err != nil {
			return err
		}
		return tx.PutFinding(young)
	}); err != nil {
		t.Fatal(err)
	}
	id := new(api.DetectorId(detector.ID))
	assertVisible := func(want api.FindingIds) {
		t.Helper()
		got, rejected := filterCall(s, ctx, "GetFindings", &api.GetFindingsInput{DetectorId: id, FindingIds: api.FindingIds{"expired", "retained"}})
		if rejected != nil {
			t.Fatal(rejected)
		}
		ids := api.FindingIds{}
		for _, finding := range got.(*api.GetFindingsOutput).Findings {
			ids = append(ids, api.FindingId(value(finding.Id)))
		}
		if !reflect.DeepEqual(ids, want) {
			t.Fatalf("GetFindings IDs = %v, want %v", ids, want)
		}
		listed, rejected := filterCall(s, ctx, "ListFindings", &api.ListFindingsInput{DetectorId: id})
		if rejected != nil {
			t.Fatal(rejected)
		}
		if !reflect.DeepEqual(listed.(*api.ListFindingsOutput).FindingIds, want) {
			t.Fatalf("ListFindings = %+v, want %v", listed, want)
		}
		in := &api.GetFindingsStatisticsInput{DetectorId: id}
		text(&in.GroupBy, "ACCOUNT")
		statistics, rejected := filterCall(s, ctx, "GetFindingsStatistics", in)
		if rejected != nil {
			t.Fatal(rejected)
		}
		groups := statistics.(*api.GetFindingsStatisticsOutput).FindingStatistics.GroupedByAccount
		if len(groups) != 1 || groups[0].TotalFindings == nil || int(*groups[0].TotalFindings) != len(want) {
			t.Fatalf("statistics include expired rows: %+v", groups)
		}
	}
	if err := manual.Advance(time.Hour - time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	assertVisible(api.FindingIds{"expired", "retained"})
	if err := manual.Advance(time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	assertVisible(api.FindingIds{"retained"})
	if _, rejected := filterCall(s, ctx, "ArchiveFindings", &api.ArchiveFindingsInput{DetectorId: id, FindingIds: api.FindingIds{"expired"}}); rejected == nil || rejected.Code != "BadRequestException" {
		t.Fatalf("archive expired finding: %v", rejected)
	}
	feedback := &api.UpdateFindingsFeedbackInput{DetectorId: id, FindingIds: api.FindingIds{"expired"}}
	text(&feedback.Feedback, "NOT_USEFUL")
	if _, rejected := filterCall(s, ctx, "UpdateFindingsFeedback", feedback); rejected != nil {
		t.Fatal(rejected)
	}
	// No scheduler has run: visibility and mutation fencing cannot depend on
	// physical cleanup winning a race with the caller.
	if err := s.repository.View(ctx, func(r Reader) error {
		row, err := r.Finding(detector.Scope, detector.ID, old.ID)
		if err == nil && (row.Archived || row.Feedback != "USEFUL") {
			t.Fatalf("expired finding was mutated: %+v", row)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
