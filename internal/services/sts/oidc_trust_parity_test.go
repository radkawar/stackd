package sts

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"stackd/internal/identity"
)

func TestOIDCSDKTrustAndProviderRoutingAWSParity(t *testing.T) {
	data, err := os.ReadFile("testdata/oidc/aws-trust.json")
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.ReplaceAll(string(data), "<source-account>", "123456789012"))
	var fixture struct {
		Source, Endpoint, Issuer string
		Cleanup                  bool `json:"cleanup_complete"`
		Scenarios                []struct {
			Scenario   string
			ObservedAt string `json:"observed_at"`
			Input      struct {
				RoleArn, RoleSessionName, WebIdentityToken string
				ProviderId                                 *string
			}
			Trust    json.RawMessage `json:"trust_policy"`
			JWKS     json.RawMessage
			ExitCode int `json:"exit_code"`
			Error    string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.Cleanup || fixture.Source == "" || fixture.Endpoint != "https://sts.us-east-1.amazonaws.com" {
		t.Fatal("missing real AWS provenance and completed cleanup")
	}
	for _, row := range fixture.Scenarios {
		if len(row.Trust) == 0 && row.Input.ProviderId == nil {
			continue
		} // Setup propagation, not a trust observation.
		t.Run(row.Scenario, func(t *testing.T) {
			now, err := time.Parse(time.RFC3339Nano, row.ObservedAt)
			if err != nil {
				t.Fatal(err)
			}
			a, input, _ := oidcHandlerFixture(t, "algorithm-RS256")
			a.provider.ARN = "arn:aws:iam::123456789012:oidc-provider/" + strings.TrimPrefix(fixture.Issuer, "https://")
			a.provider.IssuerURL = fixture.Issuer
			a.keys = OIDCKeySet{IssuerURL: fixture.Issuer, ProviderID: a.provider.ID, ProviderVersion: a.provider.Version, Keys: decodeOIDCFixtureKeys(t, row.JWKS)}
			a.role.ARN = row.Input.RoleArn
			a.role.TrustPolicy = string(row.Trust)
			a.store = identity.NewStore("123456789012")
			input.RoleArn, input.RoleSessionName, input.WebIdentityToken, input.ProviderId = aws.String(row.Input.RoleArn), aws.String(row.Input.RoleSessionName), aws.String(row.Input.WebIdentityToken), row.Input.ProviderId
			var oauth OAuthTokenSource
			if row.Input.ProviderId != nil && *row.Input.ProviderId == "graph.facebook.com" {
				// The observed rejection comes from the provider. Replay its bounded
				// error response through the real HTTP parser, never substitute an
				// identity or pretend a social OAuth token was authenticated locally.
				idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":{"message":"Bad signature","code":190}}`))
				}))
				defer idp.Close()
				oauth, err = NewHTTPOAuthTokenSource(OAuthHTTPConfig{Client: idp.Client(), FacebookDebugTokenURL: idp.URL, FacebookAppAccessToken: "configured-fixture-app-token"})
				if err != nil {
					t.Fatal(err)
				}
			}
			client, _ := oidcHandlerClient(t, a, now, oauth)
			out, err := client.AssumeRoleWithWebIdentity(context.Background(), input)
			if row.ExitCode == 0 {
				if err != nil {
					t.Fatalf("AWS allowed; local=%v", err)
				}
				if out.Credentials == nil || aws.ToString(out.Provider) != a.provider.ARN {
					t.Fatal("missing issued identity")
				}
			} else {
				match := regexp.MustCompile(`error occurred \(([^)]+)\)`).FindStringSubmatch(row.Error)
				if len(match) != 2 {
					t.Fatalf("invalid AWS error fixture: %s", row.Error)
				}
				oidcHandlerError(t, err, match[1])
				if a.issued != 0 {
					t.Fatal("AWS rejection issued a local credential")
				}
			}
		})
	}
}
