package integrations

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/apigateway"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/wafv2"
	"stackd/storage/sqlite"
	gatewaystore "stackd/storage/sqlite/apigateway"
	wafstore "stackd/storage/sqlite/wafv2"
)

// Recreating a stage at the same clock instant must not transfer an old web ACL
// association to the new stage, including after both owners reopen SQLite.
func TestWAFDoesNotProtectSameClockRecreatedRESTStage(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			scope := cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: scope.Account})
			now := clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))
			var gatewayRepository apigateway.Repository = apigateway.NewMemoryRepository(nil)
			var wafRepository wafv2.Repository = wafv2.NewMemoryRepository(nil)
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "waf.sqlite")
			open := func() {
				t.Helper()
				var err error
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				gatewayRepository, wafRepository = gatewaystore.New(db), wafstore.New(db)
			}
			if backend == "sqlite" {
				open()
			}
			var gateway *apigateway.Service
			var waf *wafv2.Service
			var gatewayHandlers, wafHandlers map[string]cloudformation.ResourceHandler
			assemble := func() {
				gateway = apigateway.New(apigateway.Config{Repository: gatewayRepository, Clock: now})
				waf = wafv2.New(wafv2.Config{Repository: wafRepository, Clock: now, Resources: WAFRESTStages{Gateway: gateway}})
				commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"apigateway": gateway, "wafv2": waf})
				gatewayHandlers, wafHandlers = CloudFormationAPIGatewayRESTHandlers(commands), CloudFormationWAFHandlers(commands)
			}
			assemble()
			t.Cleanup(func() {
				_ = waf.Close()
				_ = gateway.Close()
				if db != nil {
					_ = db.Close()
				}
			})
			request := func(kind, logical string, properties cloudformation.Properties) cloudformation.ResourceRequest {
				return cloudformation.ResourceRequest{StackID: "stack", StackName: "stack", LogicalID: logical, Token: logical + "-first", Type: kind, Scope: scope, Properties: properties}
			}
			create := func(handlers map[string]cloudformation.ResourceHandler, r *cloudformation.ResourceRequest) cloudformation.ResourceResult {
				t.Helper()
				out, err := handlers[r.Type].Create(ctx, *r)
				if err != nil {
					t.Fatalf("create %s: %v", r.Type, err)
				}
				r.PhysicalID = out.PhysicalID
				return out
			}
			api := request("AWS::ApiGateway::RestApi", "API", cloudformation.Properties{"Name": "same-clock"})
			apiResult := create(gatewayHandlers, &api)
			method := request("AWS::ApiGateway::Method", "Method", cloudformation.Properties{"RestApiId": apiResult.Ref, "ResourceId": apiResult.Attributes["RootResourceId"], "HttpMethod": "GET", "AuthorizationType": "NONE", "Integration": map[string]any{"Type": "AWS_PROXY", "IntegrationHttpMethod": "POST", "Uri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:target/invocations"}})
			create(gatewayHandlers, &method)
			deployment := request("AWS::ApiGateway::Deployment", "Deployment", cloudformation.Properties{"RestApiId": apiResult.Ref})
			deploymentResult := create(gatewayHandlers, &deployment)
			stage := request("AWS::ApiGateway::Stage", "Stage", cloudformation.Properties{"RestApiId": apiResult.Ref, "DeploymentId": deploymentResult.Ref, "StageName": "prod"})
			create(gatewayHandlers, &stage)
			acl := request("AWS::WAFv2::WebACL", "ACL", cloudformation.Properties{"Scope": "REGIONAL", "DefaultAction": map[string]any{"Block": map[string]any{}}, "VisibilityConfig": map[string]any{"MetricName": "acl", "CloudWatchMetricsEnabled": false, "SampledRequestsEnabled": false}})
			aclResult := create(wafHandlers, &acl)
			wafScope := wafv2.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
			association := request("AWS::WAFv2::WebACLAssociation", "Association", cloudformation.Properties{"ResourceArn": wafv2.RESTStageARN(wafScope, apiResult.Ref, "prod"), "WebACLArn": aclResult.Attributes["Arn"]})
			create(wafHandlers, &association)
			inspect := func(wantBlocked bool) {
				t.Helper()
				verdict, err := waf.InspectRESTStage(ctx, wafScope, apiResult.Ref, "prod", &wafv2.HTTPRequest{Method: "GET", URI: "/prod", SourceIP: "198.51.100.1"})
				if err != nil || verdict.Blocked != wantBlocked {
					t.Fatalf("InspectRESTStage = %+v, %v; want blocked %v", verdict, err, wantBlocked)
				}
			}
			inspect(true)
			stageKey := apigateway.StageKey{APIKey: apigateway.APIKey{Scope: apigateway.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}, ID: apiResult.Ref}, Name: "prod"}
			var originalCreated time.Time
			if err := gatewayRepository.View(ctx, func(r apigateway.Reader) error {
				row, err := r.Stage(stageKey)
				originalCreated = row.Created
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := gatewayHandlers[stage.Type].Delete(ctx, stage); err != nil {
				t.Fatal(err)
			}
			stage.PhysicalID, stage.Token = "", "Stage-second"
			create(gatewayHandlers, &stage)
			if err := gatewayRepository.View(ctx, func(r apigateway.Reader) error {
				row, err := r.Stage(stageKey)
				if err == nil && !row.Created.Equal(originalCreated) {
					t.Fatal("regression requires identical public creation timestamps")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			inspect(false)
			if backend == "sqlite" {
				_ = waf.Close()
				_ = gateway.Close()
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				open()
				assemble()
				inspect(false)
			}
			// Explicit association of the new stage starts enforcement again;
			// the retained old association must not be mistaken for an active one.
			association.PhysicalID, association.Token = "", "Association-second"
			create(wafHandlers, &association)
			inspect(true)
		})
	}
}
