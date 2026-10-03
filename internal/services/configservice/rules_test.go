package configservice

import (
	"context"
	"fmt"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/configservice"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func ruleTestContext(scope Scope) context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: fmt.Sprintf("arn:%s:iam::%s:root", scope.Partition, scope.AccountID), PrincipalID: scope.AccountID})
}
func ruleTestCommand(t *testing.T, s *Service, ctx context.Context, action string, input any) (any, *awswire.Error) {
	t.Helper()
	model, ok := awscatalog.LookupService("configservice")
	if !ok {
		t.Fatal("Config model missing")
	}
	op, ok := model.Operation(action)
	if !ok {
		t.Fatalf("operation missing: %s", action)
	}
	return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: input})
}
func ruleTestOK[T any](t *testing.T, s *Service, ctx context.Context, action string, input any) *T {
	t.Helper()
	out, rejected := ruleTestCommand(t, s, ctx, action, input)
	if rejected != nil {
		t.Fatalf("%s: %v", action, rejected)
	}
	typed, ok := out.(*T)
	if !ok {
		t.Fatalf("%s returned %T", action, out)
	}
	return typed
}
func ruleTestDrain(t *testing.T, s *Service) {
	t.Helper()
	result, err := s.JobDriver().RunDue(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if result.More {
		t.Fatal("rule jobs did not settle")
	}
}
func ruleTestSeed(t *testing.T, r Repository, fn func(Transaction) error) {
	t.Helper()
	if err := r.Update(t.Context(), fn); err != nil {
		t.Fatal(err)
	}
}

func TestConfigRuleManagedTransitions(t *testing.T) {
	scope := Scope{"aws", "111111111111", "us-east-1"}
	ctx := ruleTestContext(scope)
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	c := clock.NewManual(now)
	repo := NewMemoryRepository(nil)
	s := New(Config{Repository: repo, Clock: c})
	defer s.Close()
	ruleTestSeed(t, repo, func(tx Transaction) error { return tx.PutRecorder(Recorder{Scope: scope, Name: "default"}) })
	ruleTestOK[api.PutConfigRuleOutput](t, s, ctx, "PutConfigRule", &api.PutConfigRuleInput{ConfigRule: &api.ConfigRule{ConfigRuleName: new(api.ConfigRuleName("tags")), InputParameters: new(api.StringWithCharLimit1024(`{"tag1Key":"team","tag1Value":"platform,infra"}`)), Source: &api.Source{Owner: new(api.Owner("AWS")), SourceIdentifier: new(api.StringWithCharLimit256("REQUIRED_TAGS"))}}})
	appendItem := func(status string, tags map[string]string) {
		t.Helper()
		ruleTestSeed(t, repo, func(tx Transaction) error {
			item, err := tx.AppendItem(Item{Scope: scope, ResourceType: "AWS::S3::Bucket", ResourceID: "bucket", Status: status, Configuration: `{"name":"bucket"}`, CaptureTime: c.Now(), Tags: tags})
			if err != nil {
				return err
			}
			return s.evaluateItem(tx, item)
		})
	}
	compliance := func(filter api.ComplianceTypes) string {
		t.Helper()
		out := ruleTestOK[api.GetComplianceDetailsByConfigRuleOutput](t, s, ctx, "GetComplianceDetailsByConfigRule", &api.GetComplianceDetailsByConfigRuleInput{ConfigRuleName: new(api.StringWithCharLimit64("tags")), ComplianceTypes: filter})
		if len(out.EvaluationResults) != 1 {
			t.Fatalf("expected bucket evaluation, got %+v", out.EvaluationResults)
		}
		return value(out.EvaluationResults[0].ComplianceType)
	}
	appendItem("OK", nil)
	ruleTestDrain(t, s)
	if got := compliance(nil); got != "NON_COMPLIANT" {
		t.Fatalf("missing required tag: %s", got)
	}
	// Same capture timestamp, different retained sequence: the newer observation
	// must win regardless of random result-token ordering.
	appendItem("OK", map[string]string{"team": "other"})
	appendItem("OK", map[string]string{"team": "infra"})
	ruleTestDrain(t, s)
	if got := compliance(nil); got != "COMPLIANT" {
		t.Fatalf("latest matching CSV value: %s", got)
	}
	appendItem("ResourceDeleted", nil)
	ruleTestDrain(t, s)
	if got := compliance(api.ComplianceTypes{"NOT_APPLICABLE"}); got != "NOT_APPLICABLE" {
		t.Fatalf("deleted resource: %s", got)
	}
	summary := ruleTestOK[api.DescribeComplianceByConfigRuleOutput](t, s, ctx, "DescribeComplianceByConfigRule", &api.DescribeComplianceByConfigRuleInput{ComplianceTypes: api.ComplianceTypes{"INSUFFICIENT_DATA"}})
	if len(summary.ComplianceByConfigRules) != 1 || value(summary.ComplianceByConfigRules[0].Compliance.ComplianceType) != "INSUFFICIENT_DATA" {
		t.Fatalf("deleted-only rule summary: %+v", summary)
	}
	ruleTestOK[api.DeleteEvaluationResultsOutput](t, s, ctx, "DeleteEvaluationResults", &api.DeleteEvaluationResultsInput{ConfigRuleName: new(api.StringWithCharLimit64("tags"))})
	empty := ruleTestOK[api.GetComplianceDetailsByConfigRuleOutput](t, s, ctx, "GetComplianceDetailsByConfigRule", &api.GetComplianceDetailsByConfigRuleInput{ConfigRuleName: new(api.StringWithCharLimit64("tags"))})
	if len(empty.EvaluationResults) != 0 {
		t.Fatalf("evaluations retained after delete: %+v", empty)
	}
	ruleTestOK[api.StartConfigRulesEvaluationOutput](t, s, ctx, "StartConfigRulesEvaluation", &api.StartConfigRulesEvaluationInput{ConfigRuleNames: api.ReevaluateConfigRuleNames{"tags"}})
	ruleTestDrain(t, s)
	_, rejected := ruleTestCommand(t, s, ctx, "StartConfigRulesEvaluation", &api.StartConfigRulesEvaluationInput{ConfigRuleNames: api.ReevaluateConfigRuleNames{"tags"}})
	if rejected == nil || rejected.Code != "LimitExceededException" {
		t.Fatalf("reevaluation throttling: %v", rejected)
	}
	if err := c.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	ruleTestOK[api.StartConfigRulesEvaluationOutput](t, s, ctx, "StartConfigRulesEvaluation", &api.StartConfigRulesEvaluationInput{ConfigRuleNames: api.ReevaluateConfigRuleNames{"tags"}})
	ruleTestDrain(t, s)
	ruleTestOK[api.DeleteConfigRuleOutput](t, s, ctx, "DeleteConfigRule", &api.DeleteConfigRuleInput{ConfigRuleName: new(api.ConfigRuleName("tags"))})
	_, rejected = ruleTestCommand(t, s, ctx, "GetComplianceDetailsByConfigRule", &api.GetComplianceDetailsByConfigRuleInput{ConfigRuleName: new(api.StringWithCharLimit64("tags"))})
	if rejected == nil || rejected.Code != "NoSuchConfigRuleException" {
		t.Fatalf("deleted rule remained readable: %v", rejected)
	}
}

func TestConfigRuleResultTokenBoundaries(t *testing.T) {
	scope := Scope{"aws", "111111111111", "us-east-1"}
	ctx := ruleTestContext(scope)
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	c := clock.NewManual(now)
	repo := NewMemoryRepository(nil)
	s := New(Config{Repository: repo, Clock: c})
	defer s.Close()
	ruleTestSeed(t, repo, func(tx Transaction) error {
		if err := tx.PutRule(Rule{Scope: scope, Name: "custom", ID: "config-rule-custom", ARN: "arn:" + scope.Partition + ":config:" + scope.Region + ":" + scope.AccountID + ":config-rule/config-rule-custom", Owner: "CUSTOM_LAMBDA", CreatedAt: now}); err != nil {
			return err
		}
		for _, run := range []EvaluationRun{
			{Scope: scope, Token: "active", RuleName: "custom", Status: "RUNNING", CreatedAt: now, Due: now.Add(time.Minute)},
			{Scope: scope, Token: "pending", RuleName: "custom", Status: "PENDING", CreatedAt: now, Due: now.Add(time.Hour)},
			{Scope: scope, Token: "finished", RuleName: "custom", Status: "SUCCEEDED", CreatedAt: now, Due: now.Add(time.Minute)},
		} {
			if err := tx.PutEvaluationRun(run); err != nil {
				return err
			}
		}
		return nil
	})
	evaluation := func(kind string, at time.Time) api.Evaluation {
		return api.Evaluation{ComplianceResourceId: new(api.BaseResourceId("bucket")), ComplianceResourceType: new(api.StringWithCharLimit256("AWS::S3::Bucket")), ComplianceType: new(api.ComplianceType(kind)), OrderingTimestamp: &at}
	}
	submit := func(token string, evals ...api.Evaluation) *api.PutEvaluationsInput {
		return &api.PutEvaluationsInput{ResultToken: new(api.String(token)), Evaluations: evals}
	}
	for _, token := range []string{"unknown", "pending", "finished"} {
		_, rejected := ruleTestCommand(t, s, ctx, "PutEvaluations", submit(token, evaluation("COMPLIANT", now)))
		if rejected == nil || rejected.Code != "InvalidResultTokenException" {
			t.Fatalf("%s token accepted: %v", token, rejected)
		}
	}
	other := scope
	other.Region = "us-west-2"
	_, rejected := ruleTestCommand(t, s, ruleTestContext(other), "PutEvaluations", submit("active", evaluation("COMPLIANT", now)))
	if rejected == nil || rejected.Code != "InvalidResultTokenException" {
		t.Fatalf("cross-region result token accepted: %v", rejected)
	}
	ruleTestOK[api.PutEvaluationsOutput](t, s, ctx, "PutEvaluations", submit("active", evaluation("COMPLIANT", now), evaluation("NON_COMPLIANT", now.Add(-time.Hour))))
	// A token admits multiple result batches during one real invocation; old
	// OrderingTimestamp values must not overwrite a newer batch.
	ruleTestOK[api.PutEvaluationsOutput](t, s, ctx, "PutEvaluations", submit("active", evaluation("NON_COMPLIANT", now.Add(-time.Minute))))
	dry := submit("", evaluation("NON_COMPLIANT", now.Add(time.Hour)))
	dry.TestMode = new(api.Boolean(true))
	ruleTestOK[api.PutEvaluationsOutput](t, s, ctx, "PutEvaluations", dry)
	out := ruleTestOK[api.GetComplianceDetailsByConfigRuleOutput](t, s, ctx, "GetComplianceDetailsByConfigRule", &api.GetComplianceDetailsByConfigRuleInput{ConfigRuleName: new(api.StringWithCharLimit64("custom"))})
	if len(out.EvaluationResults) != 1 || value(out.EvaluationResults[0].ComplianceType) != "COMPLIANT" || !out.EvaluationResults[0].EvaluationResultIdentifier.OrderingTimestamp.Equal(now) {
		t.Fatalf("stale or test-mode result overwrote evaluation: %+v", out.EvaluationResults)
	}
	if err := c.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	_, rejected = ruleTestCommand(t, s, ctx, "PutEvaluations", submit("active", evaluation("NON_COMPLIANT", now.Add(time.Minute))))
	if rejected == nil || rejected.Code != "InvalidResultTokenException" {
		t.Fatalf("token valid at expiry: %v", rejected)
	}
	denied := awsctx.FromContext(ctx)
	denied.PrincipalARN = "arn:aws:iam::111111111111:user/no-config"
	denied.PrincipalID = "AIDANOCONFIG"
	_, rejected = ruleTestCommand(t, s, awsctx.WithMetadata(ctx, denied), "DescribeConfigRules", &api.DescribeConfigRulesInput{})
	if rejected == nil || rejected.Code != "AccessDenied" && rejected.Code != "AccessDeniedException" {
		t.Fatalf("Config read bypassed IAM: %v", rejected)
	}
}

func TestConfigAggregationCurrentAuthorizationAndHistory(t *testing.T) {
	owner := Scope{"aws", "111111111111", "us-east-1"}
	same := Scope{"aws", owner.AccountID, "us-west-2"}
	source := Scope{"aws", "222222222222", "us-west-2"}
	ctx := ruleTestContext(owner)
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	repo := NewMemoryRepository(nil)
	s := New(Config{Repository: repo, Clock: clock.NewManual(now)})
	defer s.Close()
	seed := func(scope Scope, id, status, configuration string) {
		t.Helper()
		ruleTestSeed(t, repo, func(tx Transaction) error {
			_, err := tx.AppendItem(Item{Scope: scope, ResourceType: "AWS::S3::Bucket", ResourceID: id, Status: status, Configuration: configuration, CaptureTime: now})
			return err
		})
	}
	seed(same, "same-account", "OK", `{"version":1}`)
	seed(source, "shared", "OK", `{"version":1}`)
	seed(source, "shared", "OK", `{"version":2}`)
	ruleTestOK[api.PutConfigurationAggregatorOutput](t, s, ctx, "PutConfigurationAggregator", &api.PutConfigurationAggregatorInput{ConfigurationAggregatorName: new(api.ConfigurationAggregatorName("view")), AccountAggregationSources: api.AccountAggregationSourceList{{AccountIds: api.AccountAggregationSourceAccountList{api.AccountId(owner.AccountID), api.AccountId(source.AccountID)}, AwsRegions: api.AggregatorRegionList{"us-west-2"}}}})
	list := func() *api.ListAggregateDiscoveredResourcesOutput {
		return ruleTestOK[api.ListAggregateDiscoveredResourcesOutput](t, s, ctx, "ListAggregateDiscoveredResources", &api.ListAggregateDiscoveredResourcesInput{ConfigurationAggregatorName: new(api.ConfigurationAggregatorName("view")), ResourceType: new(api.ResourceType("AWS::S3::Bucket"))})
	}
	rows := list()
	if len(rows.ResourceIdentifiers) != 1 || value(rows.ResourceIdentifiers[0].ResourceId) != "same-account" {
		t.Fatalf("ungranted cross-account data visible: %+v", rows.ResourceIdentifiers)
	}
	grant := func(region string) {
		t.Helper()
		ruleTestOK[api.PutAggregationAuthorizationOutput](t, s, ruleTestContext(source), "PutAggregationAuthorization", &api.PutAggregationAuthorizationInput{AuthorizedAccountId: new(api.AccountId(owner.AccountID)), AuthorizedAwsRegion: new(api.AwsRegion(region))})
	}
	grant("us-west-2")
	if rows = list(); len(rows.ResourceIdentifiers) != 1 {
		t.Fatalf("grant for wrong destination Region leaked source: %+v", rows.ResourceIdentifiers)
	}
	grant(owner.Region)
	rows = list()
	if len(rows.ResourceIdentifiers) != 2 || value(rows.ResourceIdentifiers[0].ResourceId) != "same-account" || value(rows.ResourceIdentifiers[1].ResourceId) != "shared" {
		t.Fatalf("authorized deterministic source view: %+v", rows.ResourceIdentifiers)
	}
	identifier := rows.ResourceIdentifiers[1]
	get := &api.GetAggregateResourceConfigInput{ConfigurationAggregatorName: new(api.ConfigurationAggregatorName("view")), ResourceIdentifier: &identifier}
	item := ruleTestOK[api.GetAggregateResourceConfigOutput](t, s, ctx, "GetAggregateResourceConfig", get)
	if value(item.ConfigurationItem.Configuration) != `{"version":2}` {
		t.Fatalf("aggregate not reading latest retained item: %+v", item.ConfigurationItem)
	}
	page := ruleTestOK[api.ListAggregateDiscoveredResourcesOutput](t, s, ctx, "ListAggregateDiscoveredResources", &api.ListAggregateDiscoveredResourcesInput{ConfigurationAggregatorName: new(api.ConfigurationAggregatorName("view")), ResourceType: new(api.ResourceType("AWS::S3::Bucket")), Limit: new(api.Limit(1))})
	next := ruleTestOK[api.ListAggregateDiscoveredResourcesOutput](t, s, ctx, "ListAggregateDiscoveredResources", &api.ListAggregateDiscoveredResourcesInput{ConfigurationAggregatorName: new(api.ConfigurationAggregatorName("view")), ResourceType: new(api.ResourceType("AWS::S3::Bucket")), Limit: new(api.Limit(1)), NextToken: page.NextToken})
	if len(next.ResourceIdentifiers) != 1 || value(next.ResourceIdentifiers[0].ResourceId) != "shared" || next.NextToken != nil {
		t.Fatalf("pagination skipped or duplicated source: %+v", next)
	}
	ruleTestOK[api.DeleteAggregationAuthorizationOutput](t, s, ruleTestContext(source), "DeleteAggregationAuthorization", &api.DeleteAggregationAuthorizationInput{AuthorizedAccountId: new(api.AccountId(owner.AccountID)), AuthorizedAwsRegion: new(api.AwsRegion(owner.Region))})
	_, rejected := ruleTestCommand(t, s, ctx, "GetAggregateResourceConfig", get)
	if rejected == nil || rejected.Code != "ResourceNotDiscoveredException" {
		t.Fatalf("revoked source still readable: %v", rejected)
	}
	grant(owner.Region)
	seed(source, "shared", "ResourceDeleted", "")
	if rows = list(); len(rows.ResourceIdentifiers) != 1 || value(rows.ResourceIdentifiers[0].ResourceId) != "same-account" {
		t.Fatalf("deleted source resurrected from older history: %+v", rows.ResourceIdentifiers)
	}
}
