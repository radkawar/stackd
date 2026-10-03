package guardduty

import (
	"context"
	"fmt"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type filterTestAuthorizer struct {
	check func(authorization.Request) *awswire.Error
}

func (a *filterTestAuthorizer) Authorize(_ context.Context, r authorization.Request) *awswire.Error {
	if a.check != nil {
		return a.check(r)
	}
	return nil
}
func filterFixture(t *testing.T) (*Service, context.Context, Detector, *filterTestAuthorizer) {
	t.Helper()
	a := &filterTestAuthorizer{}
	s := New(Config{Authorizer: a, Clock: clock.NewManual(time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC))})
	d := Detector{Scope: Scope{"aws", "123456789012", "us-east-1"}, ID: "0123456789abcdef0123456789abcdef", Tags: map[string]string{"team": "blue"}}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: d.Partition, AccountID: d.AccountID, Region: d.Region})
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutDetector(d) }); err != nil {
		t.Fatal(err)
	}
	return s, ctx, d, a
}
func filterCall(s *Service, ctx context.Context, op string, in any) (any, *awswire.Error) {
	return s.operations[op](awsapi.WithDecodedRequest(ctx, awsapi.DecodedRequest{Input: in}))
}
func createTestFilter(t *testing.T, s *Service, ctx context.Context, d Detector, name, token string, rank int32) {
	t.Helper()
	in := &api.CreateFilterRequest{DetectorId: new(api.DetectorId(d.ID)), Name: new(api.FilterName(name)), ClientToken: new(api.ClientToken(token)), FindingCriteria: &api.FindingCriteria{Criterion: api.Criterion{"severity": {Gte: new(api.Integer(7))}}}}
	if rank != 0 {
		in.Rank = new(api.FilterRank(rank))
	}
	if _, err := filterCall(s, ctx, "CreateFilter", in); err != nil {
		t.Fatal(err)
	}
}
func getTestFilter(t *testing.T, s *Service, ctx context.Context, d Detector, name string) *api.GetFilterResponse {
	t.Helper()
	out, err := filterCall(s, ctx, "GetFilter", &api.GetFilterRequest{DetectorId: new(api.DetectorId(d.ID)), FilterName: new(api.String(name))})
	if err != nil {
		t.Fatal(err)
	}
	return out.(*api.GetFilterResponse)
}
func TestFilterNameScopedTokensAndAtomicRankUpdate(t *testing.T) {
	s, ctx, d, _ := filterFixture(t)
	createTestFilter(t, s, ctx, d, "first", "token", 1)
	createTestFilter(t, s, ctx, d, "first", "token", 1)
	createTestFilter(t, s, ctx, d, "second", "second-token", 1)
	if rank := *getTestFilter(t, s, ctx, d, "first").Rank; rank != 2 {
		t.Fatalf("rank collision did not shift prior filter: %d", rank)
	}
	changed := &api.CreateFilterRequest{DetectorId: new(api.DetectorId(d.ID)), Name: new(api.FilterName("first")), Description: new(api.FilterDescription("ignored replay")), ClientToken: new(api.ClientToken("token")), FindingCriteria: &api.FindingCriteria{Criterion: api.Criterion{"type": {Equals: api.Equals{"Recon:EC2/PortProbeUnprotectedPort"}}}}}
	if _, err := filterCall(s, ctx, "CreateFilter", changed); err != nil {
		t.Fatal(err)
	}
	if out := getTestFilter(t, s, ctx, d, "first"); value(out.Description) != "" {
		t.Fatal("token replay applied changed parameters")
	}
	if _, err := filterCall(s, ctx, "UpdateFilter", &api.UpdateFilterRequest{DetectorId: new(api.DetectorId(d.ID)), FilterName: new(api.String("first")), Rank: new(api.FilterRank(1)), Action: new(api.FilterAction("ARCHIVE"))}); err != nil {
		t.Fatal(err)
	}
	if out := getTestFilter(t, s, ctx, d, "first"); *out.Rank != 1 || value(out.Action) != "ARCHIVE" {
		t.Fatalf("update not retained: %+v", out)
	}
	if rank := *getTestFilter(t, s, ctx, d, "second").Rank; rank != 2 {
		t.Fatalf("update did not reorder sibling: %d", rank)
	}
	if _, err := filterCall(s, ctx, "UpdateFilter", &api.UpdateFilterRequest{DetectorId: new(api.DetectorId(d.ID)), FilterName: new(api.String("first")), Rank: new(api.FilterRank(2)), FindingCriteria: &api.FindingCriteria{Criterion: api.Criterion{"unknown": {Equals: api.Equals{"x"}}}}}); err == nil {
		t.Fatal("unsupported criteria succeeded")
	}
	if rank := *getTestFilter(t, s, ctx, d, "first").Rank; rank != 1 {
		t.Fatal("failed update changed rank")
	}
	changed.ClientToken = new(api.ClientToken("fresh-token"))
	if _, err := filterCall(s, ctx, "CreateFilter", changed); err == nil {
		t.Fatal("same name with a fresh token succeeded")
	}
	changed.ClientToken = new(api.ClientToken("token"))
	changed.Name = new(api.FilterName("third"))
	if _, err := filterCall(s, ctx, "CreateFilter", changed); err != nil {
		t.Fatal(err)
	}
	if value(getTestFilter(t, s, ctx, d, "third").Description) != "ignored replay" {
		t.Fatal("same token on another name did not create an independent filter")
	}
}
func TestFilterQuotaAndScopedPagination(t *testing.T) {
	s, ctx, d, _ := filterFixture(t)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		for i := range 100 {
			name := fmt.Sprintf("filter-%03d", i)
			if err := tx.PutFilter(Filter{Scope: d.Scope, DetectorID: d.ID, Name: name, ARN: filterARN(d.Scope, d.ID, name), Rank: int32(i + 1), Action: "NOOP"}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	in := &api.CreateFilterRequest{DetectorId: new(api.DetectorId(d.ID)), Name: new(api.FilterName("overflow")), FindingCriteria: &api.FindingCriteria{Criterion: api.Criterion{"severity": {Gte: new(api.Integer(7))}}}}
	if _, err := filterCall(s, ctx, "CreateFilter", in); err == nil {
		t.Fatal("101st filter succeeded")
	}
	out, err := filterCall(s, ctx, "ListFilters", &api.ListFiltersRequest{DetectorId: new(api.DetectorId(d.ID)), MaxResults: new(api.MaxResults(2))})
	if err != nil {
		t.Fatal(err)
	}
	page1 := out.(*api.ListFiltersResponse)
	if len(page1.FilterNames) != 2 || page1.FilterNames[0] != "filter-000" || page1.FilterNames[1] != "filter-001" || value(page1.NextToken) == "" {
		t.Fatalf("wrong first page: %+v", page1)
	}
	out, err = filterCall(s, ctx, "ListFilters", &api.ListFiltersRequest{DetectorId: new(api.DetectorId(d.ID)), MaxResults: new(api.MaxResults(2)), NextToken: page1.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	page2 := out.(*api.ListFiltersResponse)
	if len(page2.FilterNames) != 2 || page2.FilterNames[0] != "filter-002" {
		t.Fatalf("wrong continuation: %+v", page2)
	}
	other := d
	other.ID = "fedcba9876543210fedcba9876543210"
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutDetector(other) }); err != nil {
		t.Fatal(err)
	}
	if _, err := filterCall(s, ctx, "ListFilters", &api.ListFiltersRequest{DetectorId: new(api.DetectorId(other.ID)), NextToken: page1.NextToken}); err == nil {
		t.Fatal("cross-detector pagination token accepted")
	}
}
func TestFilterTagsAffectCurrentAuthorization(t *testing.T) {
	s, ctx, d, a := filterFixture(t)
	createTestFilter(t, s, ctx, d, "tagged", "", 0)
	arn := filterARN(d.Scope, d.ID, "tagged")
	a.check = func(r authorization.Request) *awswire.Error {
		if r.ResourceARN != arn {
			return failure("AccessDeniedException", "wrong resource", 403)
		}
		if r.Action == "guardduty:GetFilter" && (len(r.Context["aws:ResourceTag/team"]) != 1 || r.Context["aws:ResourceTag/team"][0] != "green") {
			return failure("AccessDeniedException", "tag denied", 403)
		}
		return nil
	}
	req := &api.GetFilterRequest{DetectorId: new(api.DetectorId(d.ID)), FilterName: new(api.String("tagged"))}
	if _, err := filterCall(s, ctx, "GetFilter", req); err == nil {
		t.Fatal("untagged filter was authorized")
	}
	if _, err := filterCall(s, ctx, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.GuardDutyArn(arn)), Tags: api.TagMap{"team": "green"}}); err != nil {
		t.Fatal(err)
	}
	getTestFilter(t, s, ctx, d, "tagged")
	if _, err := filterCall(s, ctx, "UntagResource", &api.UntagResourceRequest{ResourceArn: new(api.GuardDutyArn(arn)), TagKeys: api.TagKeyList{"team"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := filterCall(s, ctx, "GetFilter", req); err == nil {
		t.Fatal("removed tag remained in authorization")
	}
}

func TestFilterRankBoundariesDeletionAndExplicitEmptyDescription(t *testing.T) {
	s, ctx, d, _ := filterFixture(t)
	createTestFilter(t, s, ctx, d, "first", "", 100)
	createTestFilter(t, s, ctx, d, "second", "", 0)
	createTestFilter(t, s, ctx, d, "third", "", 100)
	first := getTestFilter(t, s, ctx, d, "first")
	if first.Description != nil || *first.Rank != 2 || *getTestFilter(t, s, ctx, d, "third").Rank != 3 {
		t.Fatal("create rank clamping or insertion failed")
	}
	if _, err := filterCall(s, ctx, "UpdateFilter", &api.UpdateFilterRequest{DetectorId: new(api.DetectorId(d.ID)), FilterName: new(api.String("first")), Rank: new(api.FilterRank(4)), Description: new(api.FilterDescription("must not commit"))}); err == nil {
		t.Fatal("out-of-bounds update rank accepted")
	}
	if getTestFilter(t, s, ctx, d, "first").Description != nil {
		t.Fatal("failed rank update changed description")
	}
	if _, err := filterCall(s, ctx, "UpdateFilter", &api.UpdateFilterRequest{DetectorId: new(api.DetectorId(d.ID)), FilterName: new(api.String("first")), Description: new(api.FilterDescription(""))}); err != nil {
		t.Fatal(err)
	}
	first = getTestFilter(t, s, ctx, d, "first")
	if first.Description == nil || *first.Description != "" {
		t.Fatal("explicit empty description lost presence")
	}
	if _, err := filterCall(s, ctx, "DeleteFilter", &api.DeleteFilterRequest{DetectorId: new(api.DetectorId(d.ID)), FilterName: new(api.String("second"))}); err != nil {
		t.Fatal(err)
	}
	after := getTestFilter(t, s, ctx, d, "first")
	if *after.Rank != 1 || *after.Version != *first.Version || !after.UpdatedAt.Equal(*first.UpdatedAt) {
		t.Fatal("delete compaction changed sibling revision or failed to compact")
	}
	if *getTestFilter(t, s, ctx, d, "third").Rank != 2 {
		t.Fatal("delete did not compact final rank")
	}
	condition := after.FindingCriteria.Criterion["severity"]
	if condition.Gte == nil || condition.GreaterThanOrEqual == nil || *condition.Gte != 7 || *condition.GreaterThanOrEqual != 7 {
		t.Fatal("numeric aliases were not preserved in GetFilter")
	}
}
