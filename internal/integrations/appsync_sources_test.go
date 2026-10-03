package integrations

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	api "stackd/internal/awsapi/appsync"
	"stackd/internal/services/appsync"
)

func TestAppSyncSourceHTTPActualRequestAndErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/base/write" || r.URL.Query().Get("id") != "a b" || r.Header.Get("X-Resolver") != "actual" {
			t.Errorf("unexpected HTTP request: %s %s %v", r.Method, r.URL.String(), r.Header)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != `{"name":"Ada"}` {
			t.Errorf("request body = %q, error = %v", body, err)
		}
		w.Header().Set("X-Source", "actual")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"already exists"}`))
	}))
	defer server.Close()
	adapter := &AppSyncSources{}
	source := api.DataSource{Type: new(api.DataSourceType("HTTP")), HttpConfig: &api.HttpDataSourceConfig{Endpoint: new(api.String(server.URL + "/base"))}}
	result, err := adapter.Execute(t.Context(), appsync.APIRecord{}, source, map[string]any{
		"method": "POST", "resourcePath": "/write", "params": map[string]any{"query": map[string]any{"id": "a b"}, "headers": map[string]any{"X-Resolver": "actual"}, "body": map[string]any{"name": "Ada"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := result.(map[string]any)
	if response["statusCode"] != http.StatusConflict || response["body"] != `{"error":"already exists"}` || response["headers"].(map[string]any)["X-Source"] != "actual" {
		t.Fatalf("response = %#v", response)
	}
}

func TestAppSyncSourceHTTPCannotOverrideEndpointOrFollowRedirect(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer server.Close()
	adapter := &AppSyncSources{}
	source := api.DataSource{Type: new(api.DataSourceType("HTTP")), HttpConfig: &api.HttpDataSourceConfig{Endpoint: new(api.String(server.URL))}}
	for _, path := range []string{target.URL, "//" + target.Listener.Addr().String()} {
		_, err := adapter.Execute(t.Context(), appsync.APIRecord{}, source, map[string]any{"method": "GET", "resourcePath": path})
		var failure *appsync.MappingError
		if !errors.As(err, &failure) || failure.Type != "MappingTemplate" {
			t.Fatalf("endpoint override = %v", err)
		}
	}
	result, err := adapter.Execute(t.Context(), appsync.APIRecord{}, source, map[string]any{"method": "GET", "resourcePath": "/"})
	if err != nil {
		t.Fatal(err)
	}
	if result.(map[string]any)["statusCode"] != http.StatusFound || targetCalls.Load() != 0 {
		t.Fatalf("redirect escaped endpoint: %#v, target calls = %d", result, targetCalls.Load())
	}
}
