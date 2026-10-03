package guardduty

import (
	"reflect"
	"testing"

	api "stackd/internal/awsapi/guardduty"
)

func TestFindingTypeStatisticsCombineSamplesAndObservations(t *testing.T) {
	s, ctx, detector, _ := filterFixture(t)
	t.Cleanup(func() { _ = s.Close() })
	const rootType = "Policy:IAMUser/RootCredentialUsage"
	const otherType = "Stealth:IAMUser/PasswordPolicyChange"
	id := new(api.DetectorId(detector.ID))
	if _, err := filterCall(s, ctx, "CreateSampleFindings", &api.CreateSampleFindingsInput{DetectorId: id, FindingTypes: api.FindingTypes{rootType}}); err != nil {
		t.Fatal(err)
	}
	now := s.clock.Now()
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		for _, row := range []struct{ id, kind string }{{"root-one", rootType}, {"root-two", rootType}, {"policy", otherType}} {
			finding := Finding{Scope: detector.Scope, DetectorID: detector.ID, ID: row.id, Created: now, Updated: now, Count: 50, Observation: Observation{Type: row.kind, Severity: 2}}
			if err := tx.PutFinding(finding); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		criteria *api.FindingCriteria
		want     map[string]int32
	}{
		{"all", nil, map[string]int32{rootType: 3, otherType: 1}},
		{"filtered", &api.FindingCriteria{Criterion: api.Criterion{"type": {Equals: api.Equals{rootType}}}}, map[string]int32{rootType: 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := &api.GetFindingsStatisticsInput{DetectorId: id, FindingCriteria: tc.criteria}
			text(&in.GroupBy, "FINDING_TYPE")
			out, err := filterCall(s, ctx, "GetFindingsStatistics", in)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]int32{}
			for _, group := range out.(*api.GetFindingsStatisticsOutput).FindingStatistics.GroupedByFindingType {
				got[value(group.FindingType)] = int32(*group.TotalFindings)
				if group.LastGeneratedAt == nil || !now.Equal(*group.LastGeneratedAt) {
					t.Errorf("last generated = %v, want %v", group.LastGeneratedAt, now)
				}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("finding-type groups = %v, want %v (count findings, not occurrences)", got, tc.want)
			}
		})
	}
}
