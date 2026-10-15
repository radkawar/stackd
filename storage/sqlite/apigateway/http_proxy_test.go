package apigateway_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	domain "stackd/internal/services/apigateway"
	"stackd/internal/services/apigatewayexec"
	"stackd/storage/sqlite"
	store "stackd/storage/sqlite/apigateway"
)

func TestHTTPProxyTypedStateRestartRollbackAndDeployedConsumer(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "proxy.sqlite")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/site/a/b" || r.URL.RawQuery != "dup=one&dup=two" {
			t.Errorf("unexpected deployed backend request: %s", r.RequestURI)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Add("Set-Cookie", "one=1")
		w.Header().Add("Set-Cookie", "two=2")
		w.WriteHeader(201)
		_, _ = w.Write([]byte{0, 255, 'x'})
	}))
	defer backend.Close()
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	repository := store.New(db)
	owner := domain.APIKey{Scope: domain.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: "rest"}
	methodKey := domain.MethodKey{ResourceKey: domain.ResourceKey{APIKey: owner, ResourceID: "proxy"}, HTTPMethod: "ANY"}
	deploymentKey := domain.DeploymentKey{APIKey: owner, DeploymentID: "snapshot"}
	now := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	proxy := &apigatewayexec.HTTPProxyIntegration{URI: backend.URL + "/site/{path}", Method: "ANY", PathParameters: map[string]string{"path": "proxy"}}
	if err := repository.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutAPI(domain.APIRecord{Key: owner, Name: "proxy", RootResourceID: "root", Created: now}); err != nil {
			return err
		}
		if err := tx.PutResource(domain.ResourceRecord{Key: domain.ResourceKey{APIKey: owner, ResourceID: "root"}, Path: "/"}); err != nil {
			return err
		}
		if err := tx.PutResource(domain.ResourceRecord{Key: methodKey.ResourceKey, ParentID: "root", PathPart: "{proxy+}", Path: "/{proxy+}"}); err != nil {
			return err
		}
		if err := tx.PutMethod(domain.MethodRecord{Key: methodKey, AuthorizationType: "NONE", RequestParameters: map[string]bool{"method.request.path.proxy": true}}); err != nil {
			return err
		}
		if err := tx.PutIntegration(domain.IntegrationRecord{Key: methodKey, URI: proxy.URI, TimeoutMillis: 1000, HTTPProxy: proxy}); err != nil {
			return err
		}
		if err := tx.PutDeployment(domain.DeploymentRecord{Key: deploymentKey, Created: now, Resources: []domain.DeploymentResource{{ResourceID: "root", Path: "/"}, {ResourceID: "proxy", Path: "/{proxy+}"}}, Routes: []domain.DeploymentRoute{{ResourceID: "proxy", Path: "/{proxy+}", HTTPMethod: "ANY", AuthorizationType: "NONE", TimeoutMillis: 1000, HTTPProxy: proxy}}}); err != nil {
			return err
		}
		return tx.PutStage(domain.StageRecord{Key: domain.StageKey{APIKey: owner, Name: "live"}, Incarnation: 1, DeploymentID: "snapshot", Created: now, Updated: now})
	}); err != nil {
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
	rollback := errors.New("abort proxy patch")
	if err := repository.Update(ctx, func(tx domain.Transaction) error {
		method, err := tx.Method(methodKey)
		if err != nil {
			return err
		}
		method.RequestParameters["method.request.path.proxy"] = false
		if err := tx.PutMethod(method); err != nil {
			return err
		}
		integration, err := tx.Integration(methodKey)
		if err != nil {
			return err
		}
		integration.HTTPProxy.PathParameters["path"] = "wrong"
		integration.HTTPProxy.Method = "POST"
		if err := tx.PutIntegration(integration); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("rollback=%v", err)
	}
	if err := repository.View(ctx, func(r domain.Reader) error {
		method, err := r.Method(methodKey)
		if err != nil {
			return err
		}
		integration, err := r.Integration(methodKey)
		if err != nil {
			return err
		}
		if !method.RequestParameters["method.request.path.proxy"] || integration.HTTPProxy == nil || integration.HTTPProxy.Method != "ANY" || integration.HTTPProxy.URI != proxy.URI || integration.HTTPProxy.PathParameters["path"] != "proxy" {
			t.Fatalf("typed state lost after rollback/restart: %+v %+v", method, integration)
		}
		other := owner
		other.Region = "us-west-2"
		if _, err := r.Integration(domain.MethodKey{ResourceKey: domain.ResourceKey{APIKey: other, ResourceID: "proxy"}, HTTPMethod: "ANY"}); !errors.Is(err, domain.ErrNotFound) {
			t.Fatal("HTTP proxy escaped region scope")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Replace the live integration, then delete its mutable method. Neither may
	// rewrite the retained deployment URI, method or path parameter rows.
	if err := repository.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutIntegration(domain.IntegrationRecord{Key: methodKey, TimeoutMillis: 29000, Mock: &apigatewayexec.MockIntegration{StatusCode: 204}}); err != nil {
			return err
		}
		integration, err := tx.Integration(methodKey)
		if err != nil {
			return err
		}
		if integration.HTTPProxy != nil || integration.Mock == nil {
			t.Fatal("integration cutover retained obsolete proxy child rows")
		}
		return tx.DeleteMethod(methodKey)
	}); err != nil {
		t.Fatal(err)
	}
	service := domain.New(domain.Config{Repository: repository})
	defer service.Close()
	w := httptest.NewRecorder()
	apigatewayexec.New(apigatewayexec.Config{REST: service}).ServeHTTP(w, httptest.NewRequest("PATCH", apigatewayexec.Prefix+"rest/live/a/b?dup=one&dup=two", nil))
	if w.Code != 201 || w.Body.String() != string([]byte{0, 255, 'x'}) || len(w.Header().Values("Set-Cookie")) != 2 {
		t.Fatalf("retained deployment consumer=%d %v %q", w.Code, w.Header(), w.Body.String())
	}
	if err := repository.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.DeleteStage(domain.StageKey{APIKey: owner, Name: "live"}); err != nil {
			return err
		}
		if err := tx.DeleteDeployment(deploymentKey); err != nil {
			return err
		}
		_, err := tx.Deployment(deploymentKey)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatal("deleted deployment retained proxy route")
		}
		return tx.DeleteAPI(owner)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryHTTPProxyOwnedMapsNeverAlias(t *testing.T) {
	repository := domain.NewMemoryRepository(nil)
	ctx := t.Context()
	owner := domain.APIKey{Scope: domain.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: "rest"}
	key := domain.MethodKey{ResourceKey: domain.ResourceKey{APIKey: owner, ResourceID: "proxy"}, HTTPMethod: "ANY"}
	deploymentKey := domain.DeploymentKey{APIKey: owner, DeploymentID: "snapshot"}
	proxy := &apigatewayexec.HTTPProxyIntegration{URI: "http://backend.example/{path}", Method: "GET", PathParameters: map[string]string{"path": "proxy"}}
	method := domain.MethodRecord{Key: key, RequestParameters: map[string]bool{"method.request.path.proxy": true}}
	if err := repository.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutMethod(method); err != nil {
			return err
		}
		if err := tx.PutIntegration(domain.IntegrationRecord{Key: key, HTTPProxy: proxy}); err != nil {
			return err
		}
		return tx.PutDeployment(domain.DeploymentRecord{Key: deploymentKey, Routes: []domain.DeploymentRoute{{HTTPProxy: proxy}}})
	}); err != nil {
		t.Fatal(err)
	}
	proxy.PathParameters["path"] = "outside"
	method.RequestParameters["method.request.path.proxy"] = false
	for range 2 {
		if err := repository.View(ctx, func(r domain.Reader) error {
			method, err := r.Method(key)
			if err != nil {
				return err
			}
			integration, err := r.Integration(key)
			if err != nil {
				return err
			}
			deployment, err := r.Deployment(deploymentKey)
			if err != nil {
				return err
			}
			if !method.RequestParameters["method.request.path.proxy"] || integration.HTTPProxy.PathParameters["path"] != "proxy" || deployment.Routes[0].HTTPProxy.PathParameters["path"] != "proxy" {
				t.Fatal("proxy maps alias caller or reader")
			}
			method.RequestParameters["method.request.path.proxy"] = false
			integration.HTTPProxy.PathParameters["path"] = "reader"
			deployment.Routes[0].HTTPProxy.PathParameters["path"] = "reader"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
