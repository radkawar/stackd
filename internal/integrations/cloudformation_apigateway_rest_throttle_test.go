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
	"stackd/internal/services/apigatewayexec"
	"stackd/internal/services/cloudformation"
	"stackd/storage/sqlite"
	gatewaystore "stackd/storage/sqlite/apigateway"
)

func TestRESTCloudFormationMethodThrottleValidation(t *testing.T) {
	for _, test := range []struct {
		field string
		value any
	}{
		{"ThrottlingBurstLimit", -1}, {"ThrottlingBurstLimit", 0.5}, {"ThrottlingBurstLimit", "2147483648"},
		{"ThrottlingBurstLimit", nil}, {"ThrottlingRateLimit", -0.5}, {"ThrottlingRateLimit", "NaN"},
		{"ThrottlingRateLimit", "Infinity"}, {"ThrottlingRateLimit", true},
	} {
		p := map[string]any{"MethodSettings": []any{map[string]any{"ResourcePath": "/*", "HttpMethod": "*", test.field: test.value}}}
		if err := cfnRESTStageValidation(p); err == nil {
			t.Fatalf("accepted %s=%v", test.field, test.value)
		}
	}
	for _, value := range []any{0, float64(0), "0"} {
		p := map[string]any{"MethodSettings": []any{map[string]any{"ResourcePath": "/*", "HttpMethod": "*", "ThrottlingBurstLimit": value, "ThrottlingRateLimit": value}}}
		if err := cfnRESTStageValidation(p); err != nil {
			t.Fatalf("explicit zero rejected: %v", err)
		}
	}
}

func TestRESTCloudFormationStageThrottlePersistsAndExecutes(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			scope := cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: scope.Account})
			var repository apigateway.Repository = apigateway.NewMemoryRepository(nil)
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "gateway.sqlite")
			if backend == "sqlite" {
				var err error
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				repository = gatewaystore.New(db)
			}
			now := clock.NewManual(time.Date(2035, 1, 2, 0, 0, 0, 0, time.UTC))
			owner := apigateway.New(apigateway.Config{Repository: repository, Clock: now})
			t.Cleanup(func() {
				_ = owner.Close()
				if db != nil {
					_ = db.Close()
				}
			})
			commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"apigateway": owner})
			gateway := cfnRESTGateway{commands, "Stage"}
			api, err := gateway.call(ctx, "CreateRestApi", map[string]any{"name": "stage-throttle"})
			if err != nil {
				t.Fatal(err)
			}
			apiID := api["id"].(string)
			rootID := api["rootResourceId"].(string)
			if _, err := gateway.call(ctx, "PutMethod", map[string]any{"restApiId": apiID, "resourceId": rootID, "httpMethod": "GET", "authorizationType": "NONE"}); err != nil {
				t.Fatal(err)
			}
			if _, err := gateway.call(ctx, "PutIntegration", map[string]any{"restApiId": apiID, "resourceId": rootID, "httpMethod": "GET", "type": "MOCK", "requestTemplates": map[string]any{"application/json": "{\"statusCode\":200}"}}); err != nil {
				t.Fatal(err)
			}
			deployment, err := gateway.call(ctx, "CreateDeployment", map[string]any{"restApiId": apiID})
			if err != nil {
				t.Fatal(err)
			}
			request := cloudformation.ResourceRequest{StackID: "stack", StackName: "stack", LogicalID: "Stage", Token: "stage-incarnation", Type: "AWS::ApiGateway::Stage", Scope: scope, Properties: cloudformation.Properties{"RestApiId": apiID, "DeploymentId": deployment["id"], "StageName": "live", "MethodSettings": []any{map[string]any{"ResourcePath": "/*", "HttpMethod": "*", "ThrottlingBurstLimit": float64(1), "ThrottlingRateLimit": float64(2)}}}}
			result, err := gateway.Create(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			request.PhysicalID = result.PhysicalID
			route := &apigatewayexec.Route{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, APIID: apiID, Stage: "live", ResourcePath: "/", RouteKey: "GET /"}
			if _, err := owner.AdmitUsage(ctx, route, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.AdmitUsage(ctx, route, ""); err == nil {
				t.Fatal("CFN throttle accepted excess request")
			}
			if backend == "sqlite" {
				_ = owner.Close()
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				var err error
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				repository = gatewaystore.New(db)
			} else {
				_ = owner.Close()
			}
			owner = apigateway.New(apigateway.Config{Repository: repository, Clock: now})
			commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"apigateway": owner})
			gateway = cfnRESTGateway{commands, "Stage"}
			retained, err := gateway.Read(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			settings := retained["MethodSettings"].([]any)
			setting := settings[0].(map[string]any)
			if setting["ThrottlingBurstLimit"] != float64(1) || setting["ThrottlingRateLimit"] != float64(2) {
				t.Fatalf("CFN readback lost throttles: %+v", retained)
			}
			if _, err := owner.AdmitUsage(ctx, route, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.AdmitUsage(ctx, route, ""); err == nil {
				t.Fatal("persisted throttle did not execute")
			}
			request.Previous = request.Properties
			request.Properties = cloudformation.Properties{"RestApiId": apiID, "DeploymentId": deployment["id"], "StageName": "live", "MethodSettings": []any{map[string]any{"ResourcePath": "/*", "HttpMethod": "*", "ThrottlingBurstLimit": float64(0), "ThrottlingRateLimit": float64(0)}}}
			if _, err := gateway.Update(ctx, request); err != nil {
				t.Fatal(err)
			}
			if err := now.Advance(time.Hour); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.AdmitUsage(ctx, route, ""); err == nil {
				t.Fatal("CFN live zero limit did not reject request")
			}
		})
	}
}
