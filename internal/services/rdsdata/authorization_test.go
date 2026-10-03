package rdsdata

import (
	"context"
	"strings"
	"testing"

	engine "stackd/engine/rds"
	api "stackd/internal/awsapi/rdsdata"
	"stackd/internal/awsctx"
	"stackd/journal"
)

func rootContext() context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})
}
func TestDataAuthorityRejectsForeignScopeAndOrdinaryInstances(t *testing.T) {
	source := &nativeFixture{cluster: Cluster{ARN: testCluster, Engine: "aurora-postgresql", Database: "app", Status: "available", HTTPEnabled: true, Endpoint: engine.Endpoint{Address: "127.0.0.1", Port: 5432}}, username: "app", password: "local"}
	service := New(Config{Clusters: source, Secrets: source, Authorizer: source})
	defer service.Close()
	for _, resource := range []string{
		strings.Replace(testCluster, ":aws:", ":aws-cn:", 1),
		strings.Replace(testCluster, ":us-east-1:", ":us-west-2:", 1),
		strings.Replace(testCluster, ":123456789012:", ":222222222222:", 1),
		strings.Replace(testCluster, ":cluster:", ":db:", 1),
	} {
		if _, err := service.resolve(rootContext(), "ExecuteStatement", resource, testSecret, "app"); err == nil {
			t.Fatalf("accepted foreign scope or instance: %s", resource)
		}
	}
	for _, secret := range []string{
		strings.Replace(testSecret, ":aws:", ":aws-cn:", 1),
		strings.Replace(testSecret, ":us-east-1:", ":us-west-2:", 1),
		strings.Replace(testSecret, ":123456789012:", ":222222222222:", 1),
	} {
		if _, err := service.resolve(rootContext(), "ExecuteStatement", testCluster, secret, "app"); err == nil {
			t.Fatalf("accepted foreign secret scope: %s", secret)
		}
	}
	source.cluster.Engine = "postgres"
	if _, err := service.resolve(rootContext(), "ExecuteStatement", testCluster, testSecret, "app"); err == nil {
		t.Fatal("accepted non-Aurora engine")
	}
}

// Fresh native missing-resource precedence is recorded in
// testdata/aws/rds/controls.json; no live AWS engine is required to replay it.
func TestMissingClusterPrecedesSecretFailure(t *testing.T) {
	source := &nativeFixture{
		lookupErr:    failure("DBClusterNotFoundFault", "Missing cluster."),
		secretDenied: true,
	}
	service := New(Config{Clusters: source, Secrets: source, Authorizer: source})
	defer service.Close()
	_, err := service.resolve(rootContext(), "ExecuteStatement", testCluster, testSecret, "app")
	rejected := wireError(err)
	if rejected == nil || rejected.Code != "HttpEndpointNotEnabledException" || rejected.StatusCode != 400 {
		t.Fatalf("missing cluster precedence: %v", err)
	}
}
func TestDataAuditNeverRetainsSQLSecretsResultsOrNativeErrors(t *testing.T) {
	source := &nativeFixture{}
	service := New(Config{Recorder: source})
	defer service.Close()
	secret := "private-customer-value"
	input := &api.ExecuteStatementRequest{ResourceArn: new(api.Arn(testCluster)), SecretArn: new(api.Arn(testSecret)), Database: new(api.DbName(secret)), Schema: new(api.DbName(secret)), Sql: new(api.SqlStatement("SELECT '" + secret + "'")), Parameters: api.SqlParametersList{stringParameter(secret, secret)}}
	if err := service.recordCall(rootContext(), "ExecuteStatement", input, failure("DatabaseErrorException", "invalid value '"+secret+"'")); err != nil {
		t.Fatal(err)
	}
	event := source.events[0]
	if event.Category != journal.CategoryData || event.EventType != journal.EventTypeRDSData || event.EventSource != "rdsdataapi.amazonaws.com" || event.EventResources[0].Type != "AWS::RDS::DBCluster" {
		t.Fatalf("incorrect native data event projection: %#v", event)
	}
	if strings.Contains(string(event.RequestParameters)+event.ErrorMessage, secret) || len(event.ResponseElements) != 0 {
		t.Fatal("sensitive SQL content crossed the audit boundary")
	}
	if !strings.Contains(string(event.RequestParameters), "**********") || event.ErrorCode != "DatabaseErrorException" {
		t.Fatalf("sanitized result lost diagnostic shape: %#v", event)
	}
}
