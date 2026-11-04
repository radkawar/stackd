package lambda

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"stackd/internal/gateway"
)

type unavailableURLActivity struct{ calls int }

func (a *unavailableURLActivity) RecordActivity(context.Context, string, string) error {
	a.calls++
	return errors.New("activity reporting unavailable")
}

type unavailableURLOrganizations struct{ calls int }

func (o *unavailableURLOrganizations) PrincipalOrganization(context.Context) (string, string, error) {
	o.calls++
	return "", "", errors.New("organization authority unavailable")
}

func TestFunctionResourceHostUsesLiveURLAndPublicOrigin(t *testing.T) {
	s := New(Config{Endpoint: "http://compute.example:9999", PublicEndpoint: "https://public.example:4566", EndpointDomain: "dev.example"})
	t.Cleanup(func() { _ = s.Close() })
	ref := FunctionReference{FunctionKey: FunctionKey{Scope: Scope{Partition: "aws", Account: "000000000000", Region: "us-east-1"}, Name: "function"}}
	record := FunctionURLRecord{Key: ref, ID: "current-id", Settings: FunctionURLSettings{AuthType: "AWS_IAM"}}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutFunction(FunctionRecord{Key: ref.FunctionKey, State: "Active"}); err != nil {
			return err
		}
		return tx.PutFunctionURL(record)
	}); err != nil {
		t.Fatal(err)
	}
	out, err := s.functionURLConfiguration(record)
	if err != nil || string(*out.FunctionUrl) != "https://current-id.lambda-url.us-east-1.dev.example:4566/" {
		t.Fatalf("public URL %v: %v", out.FunctionUrl, err)
	}
	g, err := gateway.New(&gateway.Registry{}, gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	activity := &unavailableURLActivity{}
	organizations := &unavailableURLOrganizations{}
	h := NewFunctionURLHandler(s, g, activity, organizations)
	r := httptest.NewRequest("POST", "https://current-id.lambda-url.us-east-1.dev.example:4566/a%2Fb/%E2%98%83?dup=one&dup=two&plus=a+b", strings.NewReader("payload"))
	digest := sha256.Sum256([]byte("payload"))
	if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, r, hex.EncodeToString(digest[:]), "lambda", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	originalHost, originalURI := r.Host, r.URL.RequestURI()
	w := httptest.NewRecorder()
	if !h.ServeFunctionURL(w, r) || w.Code != http.StatusInternalServerError || activity.calls != 1 || organizations.calls != 1 {
		t.Fatalf("signed hostname did not reach organization authorization independently of activity reporting: status=%d activity=%d organizations=%d body=%s", w.Code, activity.calls, organizations.calls, w.Body.String())
	}
	if r.Host != originalHost || r.URL.RequestURI() != originalURI {
		t.Fatal("hostname routing mutated signed request bytes")
	}
	for _, host := range []string{"missing.lambda-url.us-east-1.dev.example", "current-id.lambda-url.eu-west-2.dev.example"} {
		w = httptest.NewRecorder()
		if !h.ServeFunctionURL(w, httptest.NewRequest("GET", "https://"+host+"/", nil)) || w.Code != http.StatusForbidden {
			t.Fatalf("foreign/missing URL %q: %d", host, w.Code)
		}
	}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.DeleteFunctionURL(ref) }); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	if !h.ServeFunctionURL(w, r) || w.Code != http.StatusForbidden {
		t.Fatalf("deleted hostname retained an owner: %d", w.Code)
	}
	w = httptest.NewRecorder()
	if h.ServeFunctionURL(w, httptest.NewRequest("GET", "https://current-id.lambda-url.us-east-1.foreign.example/", nil)) {
		t.Fatal("foreign namespace was claimed")
	}
}
