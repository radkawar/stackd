package apigateway_test

import (
	"context"
	"errors"
	"path/filepath"
	domain "stackd/internal/services/apigateway"
	"stackd/internal/services/apigatewayexec"
	"stackd/storage/sqlite"
	store "stackd/storage/sqlite/apigateway"
	"testing"
	"time"
)

func TestRESTImportedTypedStateSurvivesRestartAndRollback(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "rest.sqlite")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	repository := store.New(db)
	scope := domain.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	key := domain.APIKey{Scope: scope, ID: "rest"}
	methodKey := domain.MethodKey{ResourceKey: domain.ResourceKey{APIKey: key, ResourceID: "root"}, HTTPMethod: "OPTIONS"}
	deploymentKey := domain.DeploymentKey{APIKey: key, DeploymentID: "snapshot"}
	now := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	mock := &apigatewayexec.MockIntegration{StatusCode: 200, Headers: map[string]string{"Access-Control-Allow-Origin": "*"}, Body: "{}"}
	err = repository.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutAPI(domain.APIRecord{Key: key, Name: "imported", RootResourceID: "root", Created: now, APIKeySource: "HEADER", BinaryMediaTypes: []string{"application/octet-stream"}, GatewayResponses: map[string]apigatewayexec.GatewayResponse{"DEFAULT_4XX": {StatusCode: 403, Headers: map[string]string{"X-Error": "live"}, Templates: map[string]string{"application/json": "{\"message\":$context.error.messageString}"}}}}); err != nil {
			return err
		}
		if err := tx.PutResource(domain.ResourceRecord{Key: methodKey.ResourceKey, Path: "/"}); err != nil {
			return err
		}
		if err := tx.PutMethod(domain.MethodRecord{Key: methodKey, AuthorizationType: "NONE", Responses: map[string]domain.MethodResponse{"200": {Headers: map[string]bool{"Access-Control-Allow-Origin": false}}}}); err != nil {
			return err
		}
		if err := tx.PutIntegration(domain.IntegrationRecord{Key: methodKey, TimeoutMillis: 29000, Mock: mock}); err != nil {
			return err
		}
		if err := tx.PutDeployment(domain.DeploymentRecord{Key: deploymentKey, Created: now, APIKeySource: "HEADER", Resources: []domain.DeploymentResource{{ResourceID: "root", Path: "/"}}, Routes: []domain.DeploymentRoute{{ResourceID: "root", Path: "/", HTTPMethod: "OPTIONS", AuthorizationType: "NONE", TimeoutMillis: 29000, Mock: mock}}}); err != nil {
			return err
		}
		return tx.PutStage(domain.StageRecord{Key: domain.StageKey{APIKey: key, Name: "live"}, Incarnation: 1, DeploymentID: "snapshot", Created: now, Updated: now, MethodSettings: map[string]domain.MethodSettings{"*/*": {ThrottlingBurstLimit: new(int32(1)), ThrottlingRateLimit: new(float64(0))}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository = store.New(db)
	rollback := errors.New("rollback")
	if err := repository.Update(ctx, func(tx domain.Transaction) error {
		v, err := tx.API(key)
		if err != nil {
			return err
		}
		v.BinaryMediaTypes[0] = "image/png"
		v.GatewayResponses["DEFAULT_4XX"].Headers["X-Error"] = "not-committed"
		if err := tx.PutAPI(v); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("rollback: %v", err)
	}
	if err := repository.View(ctx, func(r domain.Reader) error {
		api, err := r.API(key)
		if err != nil {
			return err
		}
		if len(api.BinaryMediaTypes) != 1 || api.BinaryMediaTypes[0] != "application/octet-stream" || api.GatewayResponses["DEFAULT_4XX"].Headers["X-Error"] != "live" || api.GatewayResponses["DEFAULT_4XX"].Templates["application/json"] == "" {
			t.Fatalf("live API durable state: %#v", api)
		}
		method, err := r.Method(methodKey)
		if err != nil {
			return err
		}
		if _, ok := method.Responses["200"].Headers["Access-Control-Allow-Origin"]; !ok {
			t.Fatalf("method responses missing: %#v", method)
		}
		integration, err := r.Integration(methodKey)
		if err != nil {
			return err
		}
		if integration.Mock == nil || integration.Mock.Body != "{}" || integration.Mock.Headers["Access-Control-Allow-Origin"] != "*" {
			t.Fatalf("integration durable state: %#v", integration)
		}
		deployment, err := r.Deployment(deploymentKey)
		if err != nil {
			return err
		}
		if len(deployment.Routes) != 1 || deployment.Routes[0].Mock == nil || deployment.Routes[0].Mock.Headers["Access-Control-Allow-Origin"] != "*" {
			t.Fatalf("deployment durable snapshot: %#v", deployment)
		}
		stage, err := r.Stage(domain.StageKey{APIKey: key, Name: "live"})
		if err != nil {
			return err
		}
		setting := stage.MethodSettings["*/*"]
		if setting.ThrottlingBurstLimit == nil || *setting.ThrottlingBurstLimit != 1 || setting.ThrottlingRateLimit == nil || *setting.ThrottlingRateLimit != 0 {
			t.Fatalf("stage throttle durable state: %#v", setting)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryImportedConfigurationDoesNotAliasTransactions(t *testing.T) {
	repository := domain.NewMemoryRepository(nil)
	ctx := context.Background()
	key := domain.APIKey{Scope: domain.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: "rest"}
	original := domain.APIRecord{Key: key, BinaryMediaTypes: []string{"application/octet-stream"}, GatewayResponses: map[string]apigatewayexec.GatewayResponse{"DEFAULT_4XX": {Headers: map[string]string{"X": "original"}, Templates: map[string]string{"application/json": "original"}}}}
	if err := repository.Update(ctx, func(tx domain.Transaction) error { return tx.PutAPI(original) }); err != nil {
		t.Fatal(err)
	}
	original.BinaryMediaTypes[0] = "outside"
	original.GatewayResponses["DEFAULT_4XX"].Headers["X"] = "outside"
	if err := repository.View(ctx, func(r domain.Reader) error {
		row, err := r.API(key)
		if err != nil {
			return err
		}
		row.BinaryMediaTypes[0] = "reader"
		row.GatewayResponses["DEFAULT_4XX"].Templates["application/json"] = "reader"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(ctx, func(r domain.Reader) error {
		row, err := r.API(key)
		if err != nil {
			return err
		}
		if row.BinaryMediaTypes[0] != "application/octet-stream" || row.GatewayResponses["DEFAULT_4XX"].Headers["X"] != "original" || row.GatewayResponses["DEFAULT_4XX"].Templates["application/json"] != "original" {
			t.Fatalf("aliased transaction state: %#v", row)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
