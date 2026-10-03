package sts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"
	"stackd/internal/identity"
)

func TestOIDCSDKAuthorizedRolesAWSParity(t *testing.T) {
	data, err := os.ReadFile("testdata/oidc/aws-roles.json")
	if err != nil {
		t.Fatal(err)
	}
	var scope struct {
		SourceAccountID string `json:"source_account_id"`
	}
	if err := json.Unmarshal(data, &scope); err != nil {
		t.Fatal(err)
	}
	if !oidcRoleAccount.MatchString(scope.SourceAccountID) {
		t.Fatal("missing signed role ARN scope")
	}
	data = []byte(strings.ReplaceAll(string(data), "<source-account>", scope.SourceAccountID))
	var fixture struct {
		Source, Endpoint, Issuer string
		CleanupComplete          bool `json:"cleanup_complete"`
		Verified                 bool `json:"cleanup_verified"`
		Scenarios                []struct {
			Scenario   string
			ObservedAt string `json:"observed_at"`
			Input      struct{ RoleArn, RoleSessionName, WebIdentityToken string }
			Trust      json.RawMessage `json:"trust_policy"`
			JWKS       json.RawMessage
			ExitCode   int `json:"exit_code"`
			Error      string
			Control    bool
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Source == "" || fixture.Endpoint != "https://sts.us-east-1.amazonaws.com" || !fixture.CleanupComplete || !fixture.Verified {
		t.Fatal("incomplete AWS provenance or cleanup")
	}
	for _, row := range fixture.Scenarios {
		if len(row.Trust) == 0 || (row.Control && row.ExitCode != 0) {
			continue
		}
		t.Run(row.Scenario, func(t *testing.T) {
			now, err := time.Parse(time.RFC3339Nano, row.ObservedAt)
			if err != nil {
				t.Fatal(err)
			}
			a, input, _ := oidcHandlerFixture(t, "algorithm-RS256")
			a.provider.ARN = "arn:aws:iam::" + scope.SourceAccountID + ":oidc-provider/" + strings.TrimPrefix(fixture.Issuer, "https://")
			a.provider.IssuerURL = fixture.Issuer
			a.keys = OIDCKeySet{IssuerURL: fixture.Issuer, ProviderID: a.provider.ID, ProviderVersion: a.provider.Version, Keys: decodeOIDCFixtureKeys(t, row.JWKS)}
			a.role.ARN, a.role.TrustPolicy = row.Input.RoleArn, string(row.Trust)
			a.store = identity.NewStore(scope.SourceAccountID)
			input.RoleArn, input.RoleSessionName, input.WebIdentityToken = aws.String(row.Input.RoleArn), aws.String(row.Input.RoleSessionName), aws.String(row.Input.WebIdentityToken)
			client, _ := oidcHandlerClient(t, a, now, nil)
			out, err := client.AssumeRoleWithWebIdentity(context.Background(), input)
			if row.ExitCode == 0 {
				if err != nil {
					t.Fatalf("AWS allowed; local=%v", err)
				}
				c, err := a.store.Resolve(context.Background(), aws.ToString(out.Credentials.AccessKeyId))
				if err != nil {
					t.Fatal(err)
				}
				if _, present := c.SessionContext["sts:roleauthorizedbyidp"]; present {
					t.Fatal("assumption-only role authorization leaked into session context")
				}
				return
			}
			match := regexp.MustCompile(`error occurred \(([^)]+)\)`).FindStringSubmatch(row.Error)
			if len(match) != 2 {
				t.Fatalf("invalid error capture: %s", row.Error)
			}
			oidcHandlerError(t, err, match[1])
			if match[1] == "InvalidIdentityToken" {
				var apiErr smithy.APIError
				if !errors.As(err, &apiErr) || !strings.Contains(row.Error, apiErr.ErrorMessage()) {
					t.Fatalf("roles error differs: local=%v AWS=%s", err, row.Error)
				}
			}
			if a.issued != 0 {
				t.Fatal("rejected roles claim issued credentials")
			}
		})
	}
}

func TestOIDCSDKRoleAuthorizationCannotBeSpoofed(t *testing.T) {
	for _, mode := range []string{"claim flag", "mismatching roles", "unsigned roles", "different ARN case", "matching roles"} {
		t.Run(mode, func(t *testing.T) {
			a, input, now := oidcHandlerFixture(t, "algorithm-RS256")
			a.role.TrustPolicy = fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"Bool":{"sts:RoleAuthorizedByIdp":"true"}}}]}`, a.provider.ARN)
			claims := oidcHandlerClaims(t, input)
			code := "InvalidIdentityToken"
			switch mode {
			case "claim flag":
				claims["sts:RoleAuthorizedByIdp"] = true
				code = "AccessDenied"
			case "mismatching roles":
				claims[oidcRolesClaim] = []string{"arn:aws:iam::123456789012:role/another"}
			case "unsigned roles", "matching roles":
				claims[oidcRolesClaim] = []string{a.role.ARN}
			case "different ARN case":
				claims[oidcRolesClaim] = []string{strings.Replace(a.role.ARN, "web-role", "Web-Role", 1)}
			}
			if mode == "unsigned roles" {
				parts := strings.Split(aws.ToString(input.WebIdentityToken), ".")
				data, err := json.Marshal(claims)
				if err != nil {
					t.Fatal(err)
				}
				parts[1] = base64.RawURLEncoding.EncodeToString(data)
				input.WebIdentityToken = aws.String(strings.Join(parts, "."))
			} else {
				input.WebIdentityToken = aws.String(signOIDCHandlerClaims(t, claims))
			}
			client, _ := oidcHandlerClient(t, a, now, nil)
			_, err := client.AssumeRoleWithWebIdentity(context.Background(), input)
			if mode == "matching roles" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				oidcHandlerError(t, err, code)
				if a.issued != 0 {
					t.Fatal("spoofed role authorization issued credentials")
				}
			}
		})
	}
}
