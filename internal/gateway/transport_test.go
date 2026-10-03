package gateway_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	iamclient "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"

	"stackd/internal/gateway"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

type transportHeaders struct {
	base      http.RoundTripper
	userAgent string
}

func (t transportHeaders) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("User-Agent", t.userAgent)
	r.Header.Set("X-Forwarded-For", "203.0.113.1")
	r.Header.Set("Forwarded", "for=203.0.113.1;proto=https")
	r.Header.Set("X-Real-IP", "203.0.113.1")
	r.Header.Set("X-Forwarded-Proto", "https")
	return t.base.RoundTrip(r)
}

func TestSDKIAMTransportConditions(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	store := identity.NewWithRepository("123456789012", iam.NewCredentialRepository(repository, nil))
	service := iam.NewWithRepository(store, repository)
	registry := &gateway.Registry{}
	if err := registry.Register(gateway.Service{Name: "iam", SigningName: "iam", Protocol: gateway.Query, QueryVersion: "2010-05-08", Namespace: "https://iam.amazonaws.com/doc/2010-05-08/", Provider: service}); err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(registry, gateway.Config{AccountID: "123456789012", Credentials: store})
	if err != nil {
		t.Fatal(err)
	}
	plain := httptest.NewServer(g)
	t.Cleanup(plain.Close)
	secure := httptest.NewTLSServer(g)
	t.Cleanup(secure.Close)
	clientFor := func(server *httptest.Server, key, secret, userAgent string) *iamclient.Client {
		return iamclient.New(iamclient.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: &http.Client{Transport: transportHeaders{base: server.Client().Transport, userAgent: userAgent}}, RetryMaxAttempts: 1})
	}
	root := clientFor(secure, "test", "test", "stackd-test/1")
	ctx := context.Background()
	if _, err := root.CreateUser(ctx, &iamclient.CreateUserInput{UserName: aws.String("transport")}); err != nil {
		t.Fatal(err)
	}
	key, err := root.CreateAccessKey(ctx, &iamclient.CreateAccessKeyInput{UserName: aws.String("transport")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, condition, userAgent string
		server                     *httptest.Server
		allowed                    bool
	}{
		{name: "actual TLS IP and user agent", server: secure, userAgent: "stackd-test/1", condition: `"IpAddress":{"aws:SourceIp":"127.0.0.1/32"},"Bool":{"aws:SecureTransport":"true"},"StringLike":{"aws:UserAgent":"stackd-test/*"}`, allowed: true},
		{name: "forwarded TLS cannot permit HTTP", server: plain, userAgent: "stackd-test/1", condition: `"Bool":{"aws:SecureTransport":"true"}`},
		{name: "forwarded IP cannot permit peer", server: secure, userAgent: "stackd-test/1", condition: `"IpAddress":{"aws:SourceIp":"203.0.113.1/32"}`},
		{name: "different user agent rejected", server: secure, userAgent: "other/1", condition: `"StringLike":{"aws:UserAgent":"stackd-test/*"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document := `{"Statement":{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*","Condition":{` + tc.condition + `}}}`
			if _, err := root.PutUserPolicy(ctx, &iamclient.PutUserPolicyInput{UserName: aws.String("transport"), PolicyName: aws.String("Connection"), PolicyDocument: aws.String(document)}); err != nil {
				t.Fatal(err)
			}
			client := clientFor(tc.server, aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey), tc.userAgent)
			output, err := client.ListUsers(ctx, &iamclient.ListUsersInput{})
			if tc.allowed {
				if err != nil || len(output.Users) != 1 {
					t.Fatalf("ListUsers = %+v, %v", output, err)
				}
				return
			}
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDenied" {
				t.Fatalf("ListUsers error = %v; want AccessDenied", err)
			}
		})
	}
}
