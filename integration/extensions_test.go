package stackd_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"stackd"
	"stackd/extension"
)

func TestExtensionAuthenticatedDispatch(t *testing.T) {
	service := extension.Service{
		APIVersion: extension.APIVersion, Name: "example", SigningName: "example", Protocol: extension.JSON11, TargetPrefix: "Example_20260911", Operations: []string{"Inspect"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			_ = json.NewEncoder(w).Encode(extension.RequestScope(r.Context()))
		}),
	}
	handler, err := stackd.New(stackd.Config{Extensions: []extension.Service{service}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	r, err := http.NewRequest(http.MethodPost, server.URL+"/", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-amz-json-1.1")
	r.Header.Set("X-Amz-Target", "Example_20260911.Inspect")
	digest := sha256.Sum256([]byte("{}"))
	err = v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: "123456789012", SecretAccessKey: "test"}, r, hex.EncodeToString(digest[:]), "example", "eu-west-2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var scope extension.Scope
	if err := json.NewDecoder(response.Body).Decode(&scope); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || scope.AccountID != "123456789012" || scope.Region != "eu-west-2" || scope.Partition != "aws" || scope.RequestID == "" {
		t.Fatalf("status=%d scope=%#v", response.StatusCode, scope)
	}
}

func TestExtensionRejectsConflictsAndUnknownVersions(t *testing.T) {
	for _, service := range []extension.Service{
		{APIVersion: 99, Name: "example"},
		{APIVersion: extension.APIVersion, Name: "iam", SigningName: "iam", Protocol: extension.Query, QueryVersion: "2010-05-08", Namespace: "example", Operations: []string{"Inspect"}, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
	} {
		if _, err := stackd.New(stackd.Config{Extensions: []extension.Service{service}}); err == nil {
			t.Fatalf("accepted invalid extension %#v", service)
		}
	}
}
