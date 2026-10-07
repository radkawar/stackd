package opensearch

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	api "stackd/internal/awsapi/opensearch"
	"stackd/internal/awscatalog"
	"stackd/internal/gateway"
)

func TestSearchResourceHostnamePreservesSignedPathAndIncarnation(t *testing.T) {
	var nativePath string
	calls := 0
	native := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		nativePath = r.URL.EscapedPath()
		if r.Header.Get("Authorization") != "" {
			t.Error("public credentials leaked into native engine")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"found":true}`))
	}))
	t.Cleanup(native.Close)
	s := New(Config{PublicEndpoint: "http://public.example:4566", EndpointDomain: "dev.example"})
	t.Cleanup(func() { _ = s.Close() })
	key := Key{Scope: Scope{Partition: "aws", AccountID: "000000000000", Region: "us-east-1"}, Name: "search"}
	owner := Domain{Key: key, Incarnation: "first-incarnation", Status: "active", NativeEndpoint: native.URL, EngineVersion: "OpenSearch_2.19"}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.PutDomain(owner) }); err != nil {
		t.Fatal(err)
	}
	out, err := s.domainStatus(t.Context(), owner)
	if err != nil || string(*out.Endpoint) != "first-incarnation.opensearch.us-east-1.dev.example:4566" {
		t.Fatalf("public resource endpoint %v: %v", out, err)
	}
	registry := &gateway.Registry{}
	model, _ := awscatalog.LookupService("opensearch")
	if err := registry.Register(gateway.Service{Name: "opensearch", SigningName: "es", Protocol: gateway.RestJSON, Provider: s, Model: &model, Decode: api.DecodeRequest}); err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(registry, gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	request := func(host, region string) *http.Request {
		r := httptest.NewRequest("GET", "http://"+host+"/index/_doc/a%2Fb?literal=a+b&encoded=a%2Bb", nil)
		digest := sha256.Sum256(nil)
		if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, r, hex.EncodeToString(digest[:]), "es", region, time.Now()); err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := request(string(*out.Endpoint), "us-east-1")
	originalHost, originalURI := r.Host, r.URL.RequestURI()
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusOK || nativePath != "/index/_doc/a%2Fb" || calls != 1 {
		t.Fatalf("signed native resource routing: %d %s native=%q calls=%d", w.Code, w.Body.String(), nativePath, calls)
	}
	if r.Host != originalHost || r.URL.RequestURI() != originalURI {
		t.Fatal("public signed request was rewritten")
	}
	w = httptest.NewRecorder()
	g.ServeHTTP(w, request("first-incarnation.opensearch.eu-west-2.dev.example:4566", "eu-west-2"))
	if w.Code == http.StatusOK || calls != 1 {
		t.Fatalf("foreign region reached the engine: %d calls=%d", w.Code, calls)
	}
	foreign := request(string(*out.Endpoint), "us-east-1")
	digest := sha256.Sum256(nil)
	if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "222222222222", SecretAccessKey: "test"}, foreign, hex.EncodeToString(digest[:]), "es", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	g.ServeHTTP(w, foreign)
	if w.Code != http.StatusForbidden || calls != 1 {
		t.Fatalf("foreign account reached unshared engine: %d calls=%d", w.Code, calls)
	}
	owner.Incarnation = "replacement-incarnation"
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.PutDomain(owner) }); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code == http.StatusOK || calls != 1 {
		t.Fatalf("old incarnation reached replacement engine: %d calls=%d", w.Code, calls)
	}
	w = httptest.NewRecorder()
	g.ServeHTTP(w, request("replacement-incarnation.opensearch.us-east-1.dev.example:4566", "us-east-1"))
	if w.Code != http.StatusOK || calls != 2 {
		t.Fatalf("replacement owner did not route: %d %s calls=%d", w.Code, w.Body.String(), calls)
	}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.DeleteDomain(key) }); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	g.ServeHTTP(w, request("replacement-incarnation.opensearch.us-east-1.dev.example:4566", "us-east-1"))
	if w.Code == http.StatusOK || calls != 2 {
		t.Fatalf("deleted owner reached engine: %d calls=%d", w.Code, calls)
	}
}
