package apigatewayv2_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/apigatewayv2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/apigatewayv2"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/apigatewayv2"
)

func ownershipContext(t *testing.T) context.Context {
	t.Helper()
	return awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111122223333", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111122223333:root", PrincipalID: "111122223333"})
}

func ownershipRepository(t *testing.T, kind string) (service.Repository, func() service.Repository) {
	t.Helper()
	if kind == "memory" {
		repository := service.NewMemoryRepository(nil)
		return repository, func() service.Repository { return repository }
	}
	path := filepath.Join(t.TempDir(), "gateway.db")
	var db *sql.DB
	open := func() service.Repository {
		t.Helper()
		var err error
		db, err = sqlite.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		return backend.New(db)
	}
	repository := open()
	t.Cleanup(func() { _ = db.Close() })
	return repository, func() service.Repository {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		return open()
	}
}

// These are internal commands with generated DTOs, exactly the boundary used by
// CFN adapters. HTTP wire validation is not part of the ownership transaction.
func ownershipCommand(t *testing.T, s *service.Service, ctx context.Context, action string, fields map[string]any) (map[string]any, *awswire.Error) {
	t.Helper()
	input, err := api.NewInput(action)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, input); err != nil {
		t.Fatal(err)
	}
	model, _ := awscatalog.LookupService("apigatewayv2")
	operation, ok := model.Operation(action)
	if !ok {
		t.Fatalf("missing operation %s", action)
	}
	output, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
	if rejected != nil {
		return nil, rejected
	}
	raw, err = json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result, nil
}

func ownershipCall(t *testing.T, s *service.Service, ctx context.Context, action string, fields map[string]any) map[string]any {
	t.Helper()
	out, rejected := ownershipCommand(t, s, ctx, action, fields)
	if rejected != nil {
		t.Fatalf("%s: %v", action, rejected)
	}
	return out
}

type ownershipCapture struct {
	kind                string
	owner               service.ResourceOwner
	create, read, patch map[string]any
}

func ownershipFixture(t *testing.T, s *service.Service, ctx context.Context, protocol string) ([]ownershipCapture, string, string) {
	t.Helper()
	var rows []ownershipCapture
	create := func(kind, idField string, fields map[string]any) string {
		t.Helper()
		owner := service.ResourceOwner{StackID: "stack-one", LogicalID: kind, Token: "incarnation-one"}
		out := ownershipCall(t, s, service.WithResourceOwner(ctx, owner), "Create"+kind, fields)
		id, ok := out[idField].(string)
		if !ok || id == "" {
			t.Fatalf("Create%s omitted %s: %#v", kind, idField, out)
		}
		rows = append(rows, ownershipCapture{kind: kind, owner: owner, create: fields})
		return id
	}
	apiInput := map[string]any{"name": "OwnedApi", "protocolType": protocol}
	if protocol == "WEBSOCKET" {
		apiInput["routeSelectionExpression"] = "$request.body.action"
	}
	apiID := create("Api", "apiId", apiInput)
	rows[len(rows)-1].read = map[string]any{"ApiId": apiID}
	rows[len(rows)-1].patch = map[string]any{"ApiId": apiID, "name": "UpdatedApi"}
	functionARN := "arn:aws:lambda:us-east-1:111122223333:function:OwnedFunction"
	invocationURI := "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/" + functionARN + "/invocations"
	integrationInput := map[string]any{"ApiId": apiID, "integrationType": "AWS_PROXY", "integrationUri": functionARN, "payloadFormatVersion": "2.0"}
	if protocol == "WEBSOCKET" {
		integrationInput["integrationUri"], integrationInput["payloadFormatVersion"] = invocationURI, "1.0"
	}
	integrationID := create("Integration", "integrationId", integrationInput)
	rows[len(rows)-1].read = map[string]any{"ApiId": apiID, "IntegrationId": integrationID}
	rows[len(rows)-1].patch = map[string]any{"ApiId": apiID, "IntegrationId": integrationID, "description": "UpdatedIntegration"}
	authorizerInput := map[string]any{"ApiId": apiID, "name": "OwnedAuthorizer", "authorizerType": "JWT", "identitySource": []string{"$request.header.Authorization"}, "jwtConfiguration": map[string]any{"issuer": "https://issuer.example", "audience": []string{"owned"}}}
	if protocol == "WEBSOCKET" {
		authorizerInput = map[string]any{"ApiId": apiID, "name": "OwnedAuthorizer", "authorizerType": "REQUEST", "authorizerUri": invocationURI, "identitySource": []string{"route.request.header.Authorization"}}
	}
	authorizerID := create("Authorizer", "authorizerId", authorizerInput)
	rows[len(rows)-1].read = map[string]any{"ApiId": apiID, "AuthorizerId": authorizerID}
	rows[len(rows)-1].patch = map[string]any{"ApiId": apiID, "AuthorizerId": authorizerID, "name": "UpdatedAuthorizer"}
	routeInput := map[string]any{"ApiId": apiID, "routeKey": "$default", "target": "integrations/" + integrationID}
	if protocol == "WEBSOCKET" {
		routeInput["routeResponseSelectionExpression"] = "$default"
	}
	routeID := create("Route", "routeId", routeInput)
	rows[len(rows)-1].read = map[string]any{"ApiId": apiID, "RouteId": routeID}
	rows[len(rows)-1].patch = map[string]any{"ApiId": apiID, "RouteId": routeID, "operationName": "UpdatedRoute"}
	if protocol == "WEBSOCKET" {
		responseID := create("RouteResponse", "routeResponseId", map[string]any{"ApiId": apiID, "RouteId": routeID, "routeResponseKey": "$default"})
		rows[len(rows)-1].read = map[string]any{"ApiId": apiID, "RouteId": routeID, "RouteResponseId": responseID}
		rows[len(rows)-1].patch = map[string]any{"ApiId": apiID, "RouteId": routeID, "RouteResponseId": responseID, "routeResponseKey": "$default"}
	}
	create("Stage", "stageName", map[string]any{"ApiId": apiID, "stageName": "owned"})
	rows[len(rows)-1].read = map[string]any{"ApiId": apiID, "StageName": "owned"}
	rows[len(rows)-1].patch = map[string]any{"ApiId": apiID, "StageName": "owned", "description": "UpdatedStage"}
	deploymentID := create("Deployment", "deploymentId", map[string]any{"ApiId": apiID, "description": "OwnedDeployment", "stageName": "owned"})
	rows[len(rows)-1].read = map[string]any{"ApiId": apiID, "DeploymentId": deploymentID}
	rows[len(rows)-1].patch = map[string]any{"ApiId": apiID, "DeploymentId": deploymentID, "description": "UpdatedDeployment"}
	return rows, apiID, routeID
}

func assertOwnershipRows(t *testing.T, repository service.Repository, ctx context.Context, apiID, routeID string, rows []ownershipCapture) {
	t.Helper()
	key := service.APIKey{Scope: service.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}, ID: apiID}
	if err := repository.View(ctx, func(r service.Reader) error {
		owners := map[string]service.ResourceOwner{}
		apiRow, err := r.API(key)
		if err != nil {
			return err
		}
		owners["Api"] = apiRow.Owner
		integrations, err := r.Integrations(key)
		if err != nil {
			return err
		}
		if len(integrations) != 1 {
			t.Fatalf("recovery minted integrations: %+v", integrations)
		}
		owners["Integration"] = integrations[0].Owner
		authorizers, err := r.Authorizers(key)
		if err != nil {
			return err
		}
		if len(authorizers) != 1 {
			t.Fatalf("recovery minted authorizers: %+v", authorizers)
		}
		owners["Authorizer"] = authorizers[0].Owner
		routes, err := r.Routes(key)
		if err != nil {
			return err
		}
		if len(routes) != 1 {
			t.Fatalf("recovery minted routes: %+v", routes)
		}
		owners["Route"] = routes[0].Owner
		responses, err := r.RouteResponses(service.ResourceKey{APIKey: key, ID: routeID})
		if err != nil {
			return err
		}
		if len(responses) > 1 {
			t.Fatalf("recovery minted route responses: %+v", responses)
		}
		if len(responses) == 1 {
			owners["RouteResponse"] = responses[0].Owner
		}
		stages, err := r.Stages(key)
		if err != nil {
			return err
		}
		if len(stages) != 1 {
			t.Fatalf("recovery minted stages: %+v", stages)
		}
		owners["Stage"] = stages[0].Owner
		deployments, err := r.Deployments(key)
		if err != nil {
			return err
		}
		if len(deployments) != 1 {
			t.Fatalf("recovery minted deployments: %+v", deployments)
		}
		owners["Deployment"] = deployments[0].Owner
		apis, err := r.APIs(key.Scope)
		if err != nil {
			return err
		}
		if len(apis) != 1 {
			t.Fatalf("recovery minted APIs: %+v", apis)
		}
		for _, row := range rows {
			if owners[row.kind] != row.owner {
				t.Errorf("%s persisted owner: got %+v want %+v", row.kind, owners[row.kind], row.owner)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAPIGatewayV2IncarnationRecoveryAndFencing(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		for _, protocol := range []string{"HTTP", "WEBSOCKET"} {
			t.Run(kind+"/"+protocol, func(t *testing.T) {
				ctx := ownershipContext(t)
				repository, reopen := ownershipRepository(t, kind)
				source := clock.NewManual(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
				s := service.New(service.Config{Repository: repository, Clock: source})
				rows, apiID, routeID := ownershipFixture(t, s, ctx, protocol)
				repository = reopen()
				source.Advance(24 * time.Hour)
				s = service.New(service.Config{Repository: repository, Clock: source})
				for _, row := range rows {
					before := ownershipCall(t, s, ctx, "Get"+row.kind, row.read)
					recovered := ownershipCall(t, s, service.WithResourceOwner(ctx, row.owner), "Create"+row.kind, row.create)
					if !reflect.DeepEqual(before, recovered) {
						t.Fatalf("%s recovery changed retained row: before=%#v recovered=%#v", row.kind, before, recovered)
					}
					for _, stale := range []service.ResourceOwner{
						{StackID: "different-stack", LogicalID: row.owner.LogicalID, Token: row.owner.Token},
						{StackID: row.owner.StackID, LogicalID: "different-logical", Token: row.owner.Token},
						{StackID: row.owner.StackID, LogicalID: row.owner.LogicalID, Token: "different-token"},
					} {
						staleContext := service.WithResourceOwner(ctx, stale)
						if _, rejected := ownershipCommand(t, s, staleContext, "Update"+row.kind, row.patch); rejected == nil || rejected.Code != "ConflictException" {
							t.Fatalf("%s stale update admitted: %v", row.kind, rejected)
						}
						if _, rejected := ownershipCommand(t, s, staleContext, "Delete"+row.kind, row.read); rejected == nil || rejected.Code != "ConflictException" {
							t.Fatalf("%s stale delete admitted: %v", row.kind, rejected)
						}
						if got := ownershipCall(t, s, staleContext, "Get"+row.kind, row.read); !reflect.DeepEqual(before, got) {
							t.Fatalf("%s rejected mutation changed row: %#v", row.kind, got)
						}
					}
					ownershipCall(t, s, service.WithResourceOwner(ctx, row.owner), "Update"+row.kind, row.patch)
					after := ownershipCall(t, s, ctx, "Get"+row.kind, row.read)
					recovered = ownershipCall(t, s, service.WithResourceOwner(ctx, row.owner), "Create"+row.kind, row.create)
					if !reflect.DeepEqual(after, recovered) {
						t.Fatalf("%s create recovery reapplied old properties", row.kind)
					}
				}
				assertOwnershipRows(t, repository, ctx, apiID, routeID, rows)
				lists := []struct {
					action string
					fields map[string]any
				}{
					{"GetApis", map[string]any{}},
					{"GetIntegrations", map[string]any{"ApiId": apiID}},
					{"GetAuthorizers", map[string]any{"ApiId": apiID}},
					{"GetRoutes", map[string]any{"ApiId": apiID}},
					{"GetStages", map[string]any{"ApiId": apiID}},
					{"GetDeployments", map[string]any{"ApiId": apiID}},
				}
				if protocol == "WEBSOCKET" {
					lists = append(lists, struct {
						action string
						fields map[string]any
					}{"GetRouteResponses", map[string]any{"ApiId": apiID, "RouteId": routeID}})
				}
				for _, list := range lists {
					items, ok := ownershipCall(t, s, ctx, list.action, list.fields)["items"].([]any)
					if !ok || len(items) != 1 {
						t.Fatalf("%s without owner returned %#v", list.action, items)
					}
				}
				for _, deleteKind := range []string{"Stage", "Deployment", "RouteResponse", "Route", "Integration", "Authorizer", "Api"} {
					for _, row := range rows {
						if row.kind != deleteKind {
							continue
						}
						ownershipCall(t, s, service.WithResourceOwner(ctx, row.owner), "Delete"+row.kind, row.read)
						if _, rejected := ownershipCommand(t, s, ctx, "Get"+row.kind, row.read); rejected == nil || rejected.Code != "NotFoundException" {
							t.Fatalf("%s owner delete retained row: %v", row.kind, rejected)
						}
					}
				}
			})
		}
	}
}

func TestAPIGatewayV2AutomaticDeploymentDoesNotInheritOwner(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			ctx := ownershipContext(t)
			repository, _ := ownershipRepository(t, kind)
			s := service.New(service.Config{Repository: repository, Clock: clock.NewManual(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))})
			rows, apiID, _ := ownershipFixture(t, s, ctx, "HTTP")
			var stageOwner, integrationOwner service.ResourceOwner
			var integrationID string
			for _, row := range rows {
				switch row.kind {
				case "Stage":
					stageOwner = row.owner
				case "Integration":
					integrationOwner = row.owner
					integrationID = row.read["IntegrationId"].(string)
				}
			}
			ownershipCall(t, s, service.WithResourceOwner(ctx, stageOwner), "UpdateStage", map[string]any{"ApiId": apiID, "StageName": "owned", "autoDeploy": true})
			ownershipCall(t, s, service.WithResourceOwner(ctx, integrationOwner), "UpdateIntegration", map[string]any{"ApiId": apiID, "IntegrationId": integrationID, "description": "DraftChange"})
			key := service.APIKey{Scope: service.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}, ID: apiID}
			if err := repository.View(ctx, func(r service.Reader) error {
				stage, err := r.Stage(service.ResourceKey{APIKey: key, ID: "owned"})
				if err != nil {
					return err
				}
				if stage.Owner != stageOwner || stage.DeploymentID == "" {
					t.Fatalf("automatic deployment changed stage owner: %+v", stage)
				}
				deployments, err := r.Deployments(key)
				if err != nil {
					return err
				}
				automatic := 0
				for _, deployment := range deployments {
					if deployment.AutoDeployed {
						automatic++
						if deployment.Owner != (service.ResourceOwner{}) {
							t.Fatalf("automatic deployment inherited CFN owner: %+v", deployment)
						}
					}
				}
				if automatic != 2 {
					t.Fatalf("expected stage activation and draft change deployments, got %d", automatic)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAPIGatewayV2NamedStageCannotBeAdopted(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			ctx := ownershipContext(t)
			repository, _ := ownershipRepository(t, kind)
			s := service.New(service.Config{Repository: repository})
			apiID := ownershipCall(t, s, ctx, "CreateApi", map[string]any{"name": "PublicApi", "protocolType": "HTTP"})["apiId"].(string)
			create := map[string]any{"ApiId": apiID, "stageName": "shared"}
			read := map[string]any{"ApiId": apiID, "StageName": "shared"}
			ownershipCall(t, s, ctx, "CreateStage", create)
			oldOwner := service.ResourceOwner{StackID: "stack-one", LogicalID: "Stage", Token: "old-token"}
			if _, rejected := ownershipCommand(t, s, service.WithResourceOwner(ctx, oldOwner), "CreateStage", create); rejected == nil || rejected.Code != "ConflictException" {
				t.Fatalf("unowned named stage adopted: %v", rejected)
			}
			ownershipCall(t, s, ctx, "DeleteStage", read)
			ownershipCall(t, s, service.WithResourceOwner(ctx, oldOwner), "CreateStage", create)
			ownershipCall(t, s, service.WithResourceOwner(ctx, oldOwner), "DeleteStage", read)
			newOwner := oldOwner
			newOwner.Token = "new-token"
			ownershipCall(t, s, service.WithResourceOwner(ctx, newOwner), "CreateStage", create)
			if _, rejected := ownershipCommand(t, s, service.WithResourceOwner(ctx, oldOwner), "DeleteStage", read); rejected == nil || rejected.Code != "ConflictException" {
				t.Fatalf("stale named-stage incarnation deleted replacement: %v", rejected)
			}
			ownershipCall(t, s, ctx, "GetStage", read)
			key := service.ResourceKey{APIKey: service.APIKey{Scope: service.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}, ID: apiID}, ID: "shared"}
			if err := repository.View(ctx, func(r service.Reader) error {
				stage, err := r.Stage(key)
				if err == nil && stage.Owner != newOwner {
					t.Fatalf("replacement stage lost incarnation: %+v", stage.Owner)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			for _, invalid := range []service.ResourceOwner{{}, {StackID: "stack"}, {StackID: "stack", LogicalID: "Stage"}} {
				if _, rejected := ownershipCommand(t, s, service.WithResourceOwner(ctx, invalid), "CreateApi", map[string]any{"name": "InvalidOwner", "protocolType": "HTTP"}); rejected == nil || rejected.Code != "BadRequestException" {
					t.Fatalf("incomplete owner admitted: %+v %v", invalid, rejected)
				}
			}
		})
	}
}
