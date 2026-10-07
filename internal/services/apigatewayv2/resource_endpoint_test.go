package apigatewayv2

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"stackd/internal/awswire"
	"stackd/internal/services/apigatewayexec"
)

func TestResourceAPIHostRetainsOwnerRegionAndDefaultDisablement(t *testing.T) {
	s := New(Config{Endpoint: "https://public.example:4566", EndpointDomain: "dev.example"})
	key := APIKey{Scope: Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, ID: "currentapi"}
	owner := APIRecord{Key: key, ProtocolType: "HTTP", Disabled: true}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.PutAPI(owner) }); err != nil {
		t.Fatal(err)
	}
	out, err := s.apiOutput(owner)
	if err != nil || string(*out.ApiEndpoint) != "https://currentapi.execute-api.us-east-1.dev.example:4566" {
		t.Fatalf("resource endpoint %v: %v", out.ApiEndpoint, err)
	}
	r := httptest.NewRequest("GET", "https://currentapi.execute-api.us-east-1.dev.example:4566/prod/a%2Fb?dup=one&dup=two", nil)
	original := r.URL.RequestURI()
	target, matched, err := s.ResourceExecution(r)
	if !matched || err != nil || !target.DefaultEndpoint || target.APIID != key.ID || target.Path != "/prod/a/b" || target.Stage != "" {
		t.Fatalf("live resource binding: %#v %t %v", target, matched, err)
	}
	_, err = s.Resolve(apigatewayexec.WithExecutionTarget(t.Context(), target), key.ID, "", "GET", target.Path)
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire.StatusCode != http.StatusForbidden {
		t.Fatalf("generated default endpoint bypassed disablement: %v", err)
	}
	if r.URL.RequestURI() != original {
		t.Fatal("resource routing rewrote the original signed path")
	}
	for _, host := range []string{"currentapi.execute-api.eu-west-2.dev.example", "unknown.execute-api.us-east-1.dev.example"} {
		_, matched, err = s.ResourceExecution(httptest.NewRequest("GET", "https://"+host+"/", nil))
		if !matched || !errors.Is(err, apigatewayexec.ErrUnknownAPI) {
			t.Fatalf("foreign or unknown owner %q: %t %v", host, matched, err)
		}
	}
	owner.ProtocolType = "WEBSOCKET"
	owner.Disabled = false
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.PutAPI(owner) }); err != nil {
		t.Fatal(err)
	}
	out, err = s.apiOutput(owner)
	if err != nil || string(*out.ApiEndpoint) != "wss://currentapi.execute-api.us-east-1.dev.example:4566" {
		t.Fatalf("websocket endpoint %v: %v", out.ApiEndpoint, err)
	}
	target, _, err = s.ResourceExecution(r)
	if err != nil || target.Stage != "prod" || target.Path != "/a%2Fb" {
		t.Fatalf("websocket stage binding: %#v %v", target, err)
	}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.DeleteAPI(key) }); err != nil {
		t.Fatal(err)
	}
	handler := apigatewayexec.New(apigatewayexec.Config{HTTP: s})
	w := httptest.NewRecorder()
	if !handler.ServeResourceExecution(w, r, nil) || w.Code != http.StatusNotFound {
		t.Fatalf("deleted host fell through to unrelated routing: %d", w.Code)
	}
}
