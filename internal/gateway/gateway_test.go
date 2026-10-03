package gateway_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	stsclient "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"stackd/internal/gateway"
	"stackd/internal/services/sts"
)

func newGateway(t *testing.T, config gateway.Config) *gateway.Gateway {
	t.Helper()
	registry := &gateway.Registry{}
	err := registry.Register(gateway.Service{Name: "sts", SigningName: "sts", Protocol: gateway.Query, QueryVersion: "2011-06-15", Namespace: sts.Namespace, Provider: sts.New()})
	if err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(registry, config)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestSDKCallerIdentity(t *testing.T) {
	server := httptest.NewServer(newGateway(t, gateway.Config{}))
	t.Cleanup(server.Close)
	for _, test := range []struct{ name, key, region, account, partition string }{
		{"default", "test", "us-east-1", "000000000000", "aws"},
		{"account", "123456789012", "eu-west-2", "123456789012", "aws"},
		{"govcloud", "123456789012", "us-gov-west-1", "123456789012", "aws-us-gov"},
		{"china", "123456789012", "cn-north-1", "123456789012", "aws-cn"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := stsclient.New(stsclient.Options{Region: test.region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(test.key, "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			output, err := client.GetCallerIdentity(context.Background(), &stsclient.GetCallerIdentityInput{})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(output.Account) != test.account || aws.ToString(output.UserId) != test.account || aws.ToString(output.Arn) != "arn:"+test.partition+":iam::"+test.account+":root" {
				t.Fatalf("unexpected identity: %#v", output)
			}
		})
	}
}

func TestSDKRejectsInvalidCredentialsAndTampering(t *testing.T) {
	for _, test := range []struct {
		name, key, secret, token, code string
		mutate                         bool
	}{
		{name: "wrong secret", key: "test", secret: "wrong", code: "SignatureDoesNotMatch"},
		{name: "unknown access key", key: "AKIAEXAMPLE0000000000", secret: "test", code: "InvalidClientTokenId"},
		{name: "unknown session", key: "test", secret: "test", token: "unknown", code: "InvalidClientTokenId"},
		{name: "changed body", key: "test", secret: "test", code: "SignatureDoesNotMatch", mutate: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := newGateway(t, gateway.Config{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.mutate {
					r.Body = io.NopCloser(strings.NewReader("Action=DeleteUser&Version=2011-06-15"))
				}
				g.ServeHTTP(w, r)
			}))
			t.Cleanup(server.Close)
			client := stsclient.New(stsclient.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(test.key, test.secret, test.token), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			_, err := client.GetCallerIdentity(context.Background(), &stsclient.GetCallerIdentityInput{})
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) || apiErr.ErrorCode() != test.code {
				t.Fatalf("got %v; want %s", err, test.code)
			}
		})
	}
}

func TestUnsignedRequestsAndHealth(t *testing.T) {
	g := newGateway(t, gateway.Config{})
	recorder := httptest.NewRecorder()
	g.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/?Action=GetCallerIdentity&Version=2011-06-15", nil))
	if recorder.Code != 400 || !strings.Contains(recorder.Body.String(), "IncompleteSignature") {
		t.Fatalf("unexpected response: %d %s", recorder.Code, recorder.Body)
	}
	recorder = httptest.NewRecorder()
	g.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/_stackd/health", nil))
	if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), "GetCallerIdentity") {
		t.Fatalf("health: %d %s", recorder.Code, recorder.Body)
	}
}
