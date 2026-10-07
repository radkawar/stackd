package integrations

import (
	"context"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/athena"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/glue"
	"testing"
)

func cfnAnalyticsTestContext() context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
}
func cfnAnalyticsTestRequest(kind string, p cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{StackID: "stack-id", StackName: "analytics", LogicalID: "Resource", Type: kind, Token: "first-incarnation", Scope: cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Properties: p}
}

// These regressions enter the real Glue/Athena command owners, not a mock CRUD provider.
func TestAnalyticsClassifierRecoveryCannotAdoptRecreatedOwner(t *testing.T) {
	ctx := cfnAnalyticsTestContext()
	owner := glue.New(glue.Config{})
	t.Cleanup(func() { _ = owner.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"glue": owner})
	h := cfnGlueClassifier{commands}
	r := cfnAnalyticsTestRequest("AWS::Glue::Classifier", cloudformation.Properties{"JsonClassifier": map[string]any{"Name": "catalog-json", "JsonPath": "$"}})
	created, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = created.PhysicalID
	if _, err = h.Create(ctx, r); err != nil {
		t.Fatalf("same-incarnation recovery: %v", err)
	}
	if err = cfnComputeRun(ctx, commands, "glue", "UpdateClassifier", map[string]any{"JsonClassifier": map[string]any{"Name": "catalog-json", "JsonPath": "$.records[*]"}}); err != nil {
		t.Fatal(err)
	}
	read, err := h.Read(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	jsonClassifier, _ := cfnComputeObject(read["JsonClassifier"])
	if jsonClassifier["JsonPath"] != "$.records[*]" {
		t.Fatalf("read must use current owner: %#v", read)
	}
	wrong := r
	wrong.Token = "replacement-incarnation"
	if err = h.Delete(ctx, wrong); err == nil {
		t.Fatal("different incarnation deleted classifier")
	}
	direct := r
	direct.CloudControl = true
	if err = h.Delete(ctx, direct); err != nil {
		t.Fatal(err)
	}
	if err = cfnComputeRun(ctx, commands, "glue", "CreateClassifier", map[string]any{"JsonClassifier": map[string]any{"Name": "catalog-json", "JsonPath": "$"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Create(ctx, r); err == nil {
		t.Fatal("recovery adopted unrelated recreated classifier")
	}
	if err = h.Delete(ctx, r); err == nil {
		t.Fatal("rollback deleted unrelated recreated classifier")
	}
}

func TestAnalyticsPreparedStatementDiscoveryAndWorkgroupResultUpdates(t *testing.T) {
	ctx := cfnAnalyticsTestContext()
	owner := athena.New(athena.Config{})
	t.Cleanup(func() { _ = owner.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"athena": owner})
	workgroup := cfnAthenaWorkGroup{commands}
	group := cfnAnalyticsTestRequest("AWS::Athena::WorkGroup", cloudformation.Properties{"Name": "analytics-group", "WorkGroupConfiguration": map[string]any{"BytesScannedCutoffPerQuery": float64(20000000), "ResultConfiguration": map[string]any{"OutputLocation": "s3://query-results/first/"}}})
	created, err := workgroup.Create(ctx, group)
	if err != nil {
		t.Fatal(err)
	}
	group.PhysicalID = created.PhysicalID
	group.Previous = group.Properties
	group.Properties = cloudformation.Properties{"Name": "analytics-group", "WorkGroupConfiguration": map[string]any{"ResultConfiguration": map[string]any{"OutputLocation": "s3://query-results/second/"}}}
	if _, err = workgroup.Update(ctx, group); err != nil {
		t.Fatal(err)
	}
	directGroup := group
	directGroup.CloudControl = true
	p, err := workgroup.Read(ctx, directGroup)
	if err != nil {
		t.Fatal(err)
	}
	configuration, _ := cfnComputeObject(p["WorkGroupConfiguration"])
	results, _ := cfnComputeObject(configuration["ResultConfiguration"])
	if results["OutputLocation"] != "s3://query-results/second/" || configuration["BytesScannedCutoffPerQuery"] != nil {
		t.Fatalf("declarative configuration did not reach owner: %#v", configuration)
	}
	statement := cfnAthenaPreparedStatement{commands}
	r := cfnAnalyticsTestRequest("AWS::Athena::PreparedStatement", cloudformation.Properties{"StatementName": "lookup", "WorkGroup": "analytics-group", "QueryStatement": "SELECT ?"})
	r.LogicalID = "Statement"
	saved, err := statement.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = saved.PhysicalID
	wrong := r
	wrong.Token = "other"
	if err = statement.Delete(ctx, wrong); err == nil {
		t.Fatal("foreign incarnation deleted statement")
	}
	rows, err := statement.List(ctx, cloudformation.ResourceRequest{Scope: r.Scope, CloudControl: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Identifier != "lookup|analytics-group" {
		t.Fatalf("statement discovery: %#v", rows)
	}
	r.Previous = r.Properties
	r.Properties = cloudformation.Properties{"StatementName": "lookup", "WorkGroup": "analytics-group", "QueryStatement": "SELECT ? + 1", "Description": "updated"}
	if _, err = statement.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	p, err = statement.Read(ctx, r)
	if err != nil || p["QueryStatement"] != "SELECT ? + 1" {
		t.Fatalf("live statement = %#v, %v", p, err)
	}
	if err = statement.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
}
