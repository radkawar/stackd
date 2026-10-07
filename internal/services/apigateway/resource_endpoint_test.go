package apigateway

import (
	"errors"
	"net/http/httptest"
	"testing"

	"stackd/internal/awsctx"
	"stackd/internal/services/apigatewayexec"
)

func TestRESTResourceHostFollowsNativeOwnerNotCaller(t *testing.T) {
	s := New(Config{Endpoint: "http://public.example:4566", EndpointDomain: "dev.example"})
	key := APIKey{Scope: Scope{Partition: "aws", AccountID: "111111111111", Region: "eu-west-2"}, ID: "restapi"}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.PutAPI(APIRecord{Key: key}) }); err != nil {
		t.Fatal(err)
	}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "222222222222", Region: "us-east-1"})
	origin, err := s.ResourceURL(ctx, key.ID)
	if err != nil || origin != "http://restapi.execute-api.eu-west-2.dev.example:4566/" {
		t.Fatalf("owner-backed REST origin %q: %v", origin, err)
	}
	r := httptest.NewRequest("GET", origin+"prod/a%2Fb?literal=a+b", nil).WithContext(ctx)
	original := r.URL.RequestURI()
	target, matched, err := s.ResourceExecution(r)
	if err != nil || !matched || !target.REST || !target.DefaultEndpoint || target.APIID != key.ID || target.Path != "/prod/a/b" {
		t.Fatalf("REST binding: %#v %t %v", target, matched, err)
	}
	if original != r.URL.RequestURI() {
		t.Fatal("REST routing changed signed bytes")
	}
	_, matched, err = s.ResourceExecution(httptest.NewRequest("GET", "http://restapi.execute-api.us-east-1.dev.example/", nil))
	if !matched || !errors.Is(err, apigatewayexec.ErrUnknownAPI) {
		t.Fatalf("foreign region claimed native owner: %t %v", matched, err)
	}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.DeleteAPI(key) }); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.ResourceExecution(r)
	if !errors.Is(err, apigatewayexec.ErrUnknownAPI) {
		t.Fatalf("deleted API remained in hostname routing: %v", err)
	}
}
