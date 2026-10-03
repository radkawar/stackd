package guardduty

import (
	"testing"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awswire"
)

func TestDetectorTagMutationRejectsUnauthorizedKeysAtomically(t *testing.T) {
	s, ctx, d, a := filterFixture(t)
	arn := detectorARN(d.Scope, d.ID)
	a.check = func(r authorization.Request) *awswire.Error {
		if r.Action == "guardduty:TagResource" {
			for _, key := range r.Context["aws:TagKeys"] {
				if key == "restricted" {
					return failure("AccessDeniedException", "restricted key", 403)
				}
			}
		}
		return nil
	}
	if _, err := filterCall(s, ctx, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.GuardDutyArn(arn)), Tags: api.TagMap{"team": "red", "restricted": "value"}}); err == nil {
		t.Fatal("unauthorized tag keys were accepted")
	}
	out, err := filterCall(s, ctx, "ListTagsForResource", &api.ListTagsForResourceRequest{ResourceArn: new(api.GuardDutyArn(arn))})
	if err != nil {
		t.Fatal(err)
	}
	tags := out.(*api.ListTagsForResourceResponse).Tags
	if tags["team"] != "blue" || len(tags) != 1 {
		t.Fatalf("denied tag mutation partially committed: %v", tags)
	}
	if _, err := filterCall(s, ctx, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.GuardDutyArn(arn)), Tags: api.TagMap{"team": "green", "environment": "test"}}); err != nil {
		t.Fatal(err)
	}
	out, err = filterCall(s, ctx, "ListTagsForResource", &api.ListTagsForResourceRequest{ResourceArn: new(api.GuardDutyArn(arn))})
	if err != nil {
		t.Fatal(err)
	}
	tags = out.(*api.ListTagsForResourceResponse).Tags
	if tags["team"] != "green" || tags["environment"] != "test" {
		t.Fatalf("tag merge lost values: %v", tags)
	}
	foreign := d.Scope
	foreign.AccountID = "999999999999"
	if _, err := filterCall(s, ctx, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.GuardDutyArn(detectorARN(foreign, d.ID))), Tags: api.TagMap{"team": "foreign"}}); err == nil {
		t.Fatal("cross-account ARN mutated local detector")
	}
}

func TestCreateFilterTagPermissionDenialCreatesNothing(t *testing.T) {
	s, ctx, d, a := filterFixture(t)
	a.check = func(r authorization.Request) *awswire.Error {
		if r.Action == "guardduty:TagResource" {
			return failure("AccessDeniedException", "tag-on-create denied", 403)
		}
		return nil
	}
	input := &api.CreateFilterRequest{DetectorId: new(api.DetectorId(d.ID)), Name: new(api.FilterName("denied")), Tags: api.TagMap{"team": "green"}, FindingCriteria: &api.FindingCriteria{Criterion: api.Criterion{"severity": {Gte: new(api.Integer(7))}}}}
	if _, err := filterCall(s, ctx, "CreateFilter", input); err == nil {
		t.Fatal("tag-on-create permission was not required")
	}
	if _, err := filterCall(s, ctx, "GetFilter", &api.GetFilterRequest{DetectorId: new(api.DetectorId(d.ID)), FilterName: new(api.String("denied"))}); err == nil {
		t.Fatal("denied create left a filter")
	}
}
