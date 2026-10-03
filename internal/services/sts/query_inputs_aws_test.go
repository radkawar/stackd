package sts_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/clock"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awscatalog"
	"stackd/internal/awstest"
	"stackd/internal/gateway"
	"stackd/internal/identity"
	"stackd/internal/services/sts"
)

func TestSTSQueryIntegersReplayAWS(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/sts/query_inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Value      string
			Code       string
			HTTPStatus int `json:"http_status"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"standalone", "gateway"} {
		t.Run(endpoint, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
			store := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: identity.NewMemoryRepository(), Clock: source})
			key, err := store.CreateAccessKey(identity.Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/query-user", ID: "AIDAQUERYUSER", UserName: "query-user"})
			if err != nil {
				t.Fatal(err)
			}
			service := sts.NewWithIdentity(store)
			var client *sdksts.Client
			var server *httptest.Server
			if endpoint == "standalone" {
				client = clientFor(t, service, key, "us-east-1")
			} else {
				model, _ := awscatalog.LookupService("sts")
				registry := &gateway.Registry{}
				if err := registry.Register(gateway.Service{Name: "sts", SigningName: "sts", Protocol: gateway.Query, QueryVersion: "2011-06-15", Namespace: sts.Namespace, Model: &model, Decode: stsapi.DecodeRequest, Provider: service}); err != nil {
					t.Fatal(err)
				}
				g, err := gateway.New(registry, gateway.Config{AccountID: "123456789012", Credentials: store})
				if err != nil {
					t.Fatal(err)
				}
				server = httptest.NewServer(g)
				t.Cleanup(server.Close)
				client = sdksts.New(sdksts.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(key.AccessKeyID, key.SecretAccessKey, ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			}
			for _, row := range fixture.Observations {
				t.Run(row.Value, func(t *testing.T) {
					out, err := client.GetSessionToken(t.Context(), &sdksts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)}, func(options *sdksts.Options) {
						options.APIOptions = append(options.APIOptions, awstest.QueryValues(url.Values{"DurationSeconds": {row.Value}}))
					})
					if row.Code != "Success" {
						requireCode(t, err, row.Code)
						var response interface{ HTTPStatusCode() int }
						if !errors.As(err, &response) || response.HTTPStatusCode() != row.HTTPStatus {
							t.Fatalf("HTTP status differs from AWS %d: %v", row.HTTPStatus, err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if out.Credentials == nil || out.Credentials.Expiration == nil || !out.Credentials.Expiration.Equal(source.Now().Add(900*time.Second)) {
						t.Fatalf("session has wrong expiry: %+v", out.Credentials)
					}
					session, err := store.Resolve(t.Context(), aws.ToString(out.Credentials.AccessKeyId))
					if err != nil || session.PrincipalID != key.PrincipalID || session.SessionToken != aws.ToString(out.Credentials.SessionToken) {
						t.Fatalf("session did not retain issuing identity: %+v, %v", session, err)
					}
					if server != nil {
						caller := sdksts.New(sdksts.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(session.AccessKeyID, session.SecretAccessKey, session.SessionToken), HTTPClient: server.Client(), RetryMaxAttempts: 1})
						who, err := caller.GetCallerIdentity(t.Context(), &sdksts.GetCallerIdentityInput{})
						if err != nil || aws.ToString(who.Arn) != key.PrincipalARN {
							t.Fatalf("issued session is not usable: %+v, %v", who, err)
						}
					}
				})
			}
		})
	}
}
