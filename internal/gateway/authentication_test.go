package gateway_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awscatalog"
	"stackd/internal/gateway"
	"stackd/internal/identity"
	"stackd/internal/services/sqs"
)

type blockedCredentials struct {
	entered chan struct{}
	release <-chan struct{}
	store   *identity.Store
}

func (c *blockedCredentials) Resolve(ctx context.Context, key string) (identity.Credential, error) {
	close(c.entered)
	select {
	case <-c.release:
		return c.store.Resolve(ctx, key)
	case <-ctx.Done():
		return identity.Credential{}, ctx.Err()
	}
}

func TestAuthenticationBodyDeadline(t *testing.T) {
	const body = `{"QueueName":"deadline-proof"}`
	for _, row := range []struct {
		name       string
		signedBody string
		limit      int64
		status     int
		code       string
	}{
		{"valid at limit", body, int64(len(body)), http.StatusOK, ""},
		{"tampered payload", `{"QueueName":"deadline-other"}`, int64(len(body)), http.StatusForbidden, "SignatureDoesNotMatch"},
		{"over limit", body, int64(len(body) - 1), http.StatusRequestEntityTooLarge, "RequestEntityTooLarge"},
	} {
		t.Run(row.name, func(t *testing.T) {
			waiting, release := context.WithCancel(t.Context())
			resolver := &blockedCredentials{entered: make(chan struct{}), release: waiting.Done(), store: identity.NewStore("000000000000")}
			provider := sqs.New()
			model, _ := awscatalog.LookupService("sqs")
			registry := &gateway.Registry{}
			if err := registry.Register(gateway.Service{Name: "sqs", SigningName: "sqs", Protocol: gateway.JSON10, TargetPrefix: model.TargetPrefix, Model: &model, Decode: api.DecodeRequest, Provider: provider}); err != nil {
				t.Fatal(err)
			}
			handler, err := gateway.New(registry, gateway.Config{Credentials: resolver, MaxBodyBytes: row.limit})
			if err != nil {
				t.Fatal(err)
			}
			headersRead := make(chan time.Time, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				headersRead <- time.Now()
				handler.ServeHTTP(w, r)
			}))
			server.Config.ReadTimeout = 500 * time.Millisecond
			server.Start()
			t.Cleanup(func() {
				release()
				server.Close()
				if err := provider.Close(); err != nil {
					t.Error(err)
				}
			})
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/x-amz-json-1.0")
			request.Header.Set("X-Amz-Target", "AmazonSQS.CreateQueue")
			digest := fmt.Sprintf("%x", sha256.Sum256([]byte(row.signedBody)))
			if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, request, digest, "sqs", "us-east-1", time.Now()); err != nil {
				t.Fatal(err)
			}
			conn, err := net.Dial("tcp", request.URL.Host)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n", request.Host, len(body)); err != nil {
				t.Fatal(err)
			}
			if err := request.Header.Write(conn); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, "\r\n"); err != nil {
				t.Fatal(err)
			}
			accepted := <-headersRead
			// Keep the body out of net/http's buffered header read. It reaches
			// the socket while the transport deadline is still in the future.
			if _, err := io.WriteString(conn, body); err != nil {
				t.Fatal(err)
			}
			if int64(len(body)) <= row.limit {
				select {
				case <-resolver.entered:
				case <-time.After(10 * time.Second):
					t.Fatal("credential resolution did not begin")
				}
				// The request reached the socket before ReadTimeout, but
				// credential resolution is held until that deadline passes.
				<-time.After(time.Until(accepted.Add(750 * time.Millisecond)))
			}
			release()
			response, err := http.ReadResponse(bufio.NewReader(conn), request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var result struct {
				QueueURL string `json:"QueueUrl"`
				Code     string `json:"__type"`
			}
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != row.status || result.Code != row.code {
				t.Fatalf("got HTTP %d %+v; want HTTP %d %s", response.StatusCode, result, row.status, row.code)
			}
			if row.status == http.StatusOK && result.QueueURL != server.URL+"/000000000000/deadline-proof" {
				t.Fatalf("signed queue creation returned %+v", result)
			}
		})
	}
}
