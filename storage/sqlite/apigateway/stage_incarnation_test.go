package apigateway_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/services/apigateway"
	"stackd/storage/sqlite"
	gatewaystore "stackd/storage/sqlite/apigateway"
)

func incarnationCommand(t *testing.T, owner *apigateway.Service, ctx context.Context, operation string, input any) any {
	t.Helper()
	model, _ := awscatalog.LookupService("apigateway")
	op, ok := model.Operation(operation)
	if !ok {
		t.Fatalf("missing operation %s", operation)
	}
	out, rejected := owner.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
	if rejected != nil {
		t.Fatalf("%s: %v", operation, rejected)
	}
	return out
}

func TestRESTStageIncarnationChangesAtSameClockAndSurvivesRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			scope := apigateway.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
			var repo apigateway.Repository = apigateway.NewMemoryRepository(nil)
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "stage.sqlite")
			if backend == "sqlite" {
				var err error
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				repo = gatewaystore.New(db)
			}
			now := clock.NewManual(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
			owner := apigateway.New(apigateway.Config{Repository: repo, Clock: now})
			t.Cleanup(func() {
				_ = owner.Close()
				if db != nil {
					_ = db.Close()
				}
			})
			created := incarnationCommand(t, owner, ctx, "CreateRestApi", &api.CreateRestApiRequest{Name: new(api.String("stage"))}).(*api.RestApi)
			id := string(*created.Id)
			resources := incarnationCommand(t, owner, ctx, "GetResources", &api.GetResourcesRequest{RestApiId: created.Id}).(*api.Resources)
			root := resources.Items[0].Id
			incarnationCommand(t, owner, ctx, "PutMethod", &api.PutMethodRequest{RestApiId: created.Id, ResourceId: root, HttpMethod: new(api.String("GET")), AuthorizationType: new(api.String("NONE"))})
			uri := "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:target/invocations"
			incarnationCommand(t, owner, ctx, "PutIntegration", &api.PutIntegrationRequest{RestApiId: created.Id, ResourceId: root, HttpMethod: new(api.String("GET")), Type: new(api.IntegrationType("AWS_PROXY")), IntegrationHttpMethod: new(api.String("POST")), Uri: new(api.String(uri))})
			deployment := incarnationCommand(t, owner, ctx, "CreateDeployment", &api.CreateDeploymentRequest{RestApiId: created.Id, StageName: new(api.String("live"))}).(*api.Deployment)
			first, err := owner.StageIncarnation(ctx, scope, id, "live")
			if err != nil || first == "" || first == "0" {
				t.Fatalf("first incarnation=%q err=%v", first, err)
			}
			incarnationCommand(t, owner, ctx, "UpdateStage", &api.UpdateStageRequest{RestApiId: created.Id, StageName: new(api.String("live")), PatchOperations: api.ListOfPatchOperation{{Op: new(api.Op("replace")), Path: new(api.String("/description")), Value: new(api.String("changed"))}}})
			updated, err := owner.StageIncarnation(ctx, scope, id, "live")
			if err != nil || updated != first {
				t.Fatalf("update changed incarnation=%q want=%q err=%v", updated, first, err)
			}
			incarnationCommand(t, owner, ctx, "DeleteStage", &api.DeleteStageRequest{RestApiId: created.Id, StageName: new(api.String("live"))})
			if backend == "sqlite" {
				_ = owner.Close()
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				repo = gatewaystore.New(db)
				owner = apigateway.New(apigateway.Config{Repository: repo, Clock: now})
			}
			incarnationCommand(t, owner, ctx, "CreateStage", &api.CreateStageRequest{RestApiId: created.Id, StageName: new(api.String("live")), DeploymentId: deployment.Id})
			second, err := owner.StageIncarnation(ctx, scope, id, "live")
			if err != nil || second == first || second == "0" {
				t.Fatalf("same-clock recreate incarnation=%q old=%q err=%v", second, first, err)
			}
			incarnationCommand(t, owner, ctx, "DeleteStage", &api.DeleteStageRequest{RestApiId: created.Id, StageName: new(api.String("live"))})
			incarnationCommand(t, owner, ctx, "CreateDeployment", &api.CreateDeploymentRequest{RestApiId: created.Id, StageName: new(api.String("live"))})
			third, err := owner.StageIncarnation(ctx, scope, id, "live")
			if err != nil || third == second || third == first {
				t.Fatalf("deployment-created incarnation=%q previous=%q,%q err=%v", third, first, second, err)
			}
		})
	}
}
