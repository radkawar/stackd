package guardduty

import (
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awsctx"
	"testing"
)

func TestCloudFormationFilterStaleMutationPreservesNativeControl(t *testing.T) {
	scope := Scope{"aws", "123456789012", "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: scope.AccountID})
	s := New(Config{})
	defer s.Close()
	id := "0123456789abcdef0123456789abcdef"
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		return tx.PutDetector(Detector{Scope: scope, ID: id, ARN: detectorARN(scope, id)})
	}); e != nil {
		t.Fatal(e)
	}
	input := &api.CreateFilterRequest{DetectorId: new(api.DetectorId(id)), Name: new(api.FilterName("security-filter")), ClientToken: new(api.ClientToken("first")), Action: new(api.FilterAction("ARCHIVE")), FindingCriteria: &api.FindingCriteria{Criterion: api.Criterion{"severity": {Gte: new(api.Integer(7))}}}, Tags: api.TagMap{"stackd:cloudformation:owner": "stack-resource", "stackd:cloudformation:create-token": "first"}}
	owner := WithCloudFormationOwnership(ctx, CloudFormationOwnership{Owner: "stack-resource", Token: "first"})
	if _, e := filterCall(s, owner, "CreateFilter", input); e != nil {
		t.Fatal(e)
	}
	stale := WithCloudFormationOwnership(ctx, CloudFormationOwnership{Owner: "stack-resource", Token: "second"})
	if _, e := filterCall(s, stale, "UpdateFilter", &api.UpdateFilterRequest{DetectorId: input.DetectorId, FilterName: new(api.String("security-filter")), Action: new(api.FilterAction("NOOP"))}); e == nil {
		t.Fatal("stale incarnation changed source filter")
	}
	if _, e := filterCall(s, stale, "DeleteFilter", &api.DeleteFilterRequest{DetectorId: input.DetectorId, FilterName: new(api.String("security-filter"))}); e == nil {
		t.Fatal("stale incarnation deleted source filter")
	}
	live := getTestFilter(t, s, ctx, Detector{Scope: scope, ID: id}, "security-filter")
	if value(live.Action) != "ARCHIVE" {
		t.Fatal("rejected stale mutation changed filter action")
	}
	if _, e := filterCall(s, owner, "DeleteFilter", &api.DeleteFilterRequest{DetectorId: input.DetectorId, FilterName: new(api.String("security-filter"))}); e != nil {
		t.Fatal(e)
	}
}
