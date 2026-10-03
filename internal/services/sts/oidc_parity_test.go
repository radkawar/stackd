package sts

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func oidcFixtureKeys(t *testing.T) []OIDCSigningKey {
	t.Helper()
	data, err := os.ReadFile("testdata/oidc/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	return decodeOIDCFixtureKeys(t, data)
}
func decodeOIDCFixtureKeys(t *testing.T, data []byte) []OIDCSigningKey {
	t.Helper()
	var document struct {
		Keys []struct {
			ID           string `json:"kid"`
			Type         string `json:"kty"`
			Algorithm    string `json:"alg"`
			Use          string `json:"use"`
			N, E         string
			Curve        string `json:"crv"`
			X, Y         string
			Operations   []string `json:"key_ops"`
			Certificates []string `json:"x5c"`
		}
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	var keys []OIDCSigningKey
	for _, key := range document.Keys {
		converted := OIDCSigningKey{ID: key.ID, Type: key.Type, Algorithm: key.Algorithm, Use: key.Use, N: key.N, E: key.E, Curve: key.Curve, X: key.X, Y: key.Y, Operations: key.Operations}
		for _, certificate := range key.Certificates {
			der, err := base64.StdEncoding.DecodeString(certificate)
			if err != nil {
				t.Fatal(err)
			}
			converted.Certificates = append(converted.Certificates, der)
		}
		keys = append(keys, converted)
	}
	return keys
}

func TestOIDCAWSJWTParity(t *testing.T) {
	paths, err := filepath.Glob("testdata/oidc/aws*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if filepath.Base(path) == "aws-roles.json" {
			// These outcomes depend on the requested RoleArn and role trust.
			// TestOIDCSDKAuthorizedRolesAWSParity replays them through the full API.
			continue
		}
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Source, Endpoint, Issuer string
				Cleanup                  bool `json:"cleanup_complete"`
				Scenarios                []struct {
					Scenario   string
					JWKS       json.RawMessage
					Input      struct{ WebIdentityToken, ProviderId string }
					Output     struct{ SubjectFromWebIdentityToken, Audience, SourceIdentity string }
					ExitCode   int `json:"exit_code"`
					Error      string
					ObservedAt string `json:"observed_at"`
				}
			}
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			if !fixture.Cleanup || fixture.Source == "" || fixture.Endpoint != "https://sts.us-east-1.amazonaws.com" {
				t.Fatal("missing AWS provenance or cleanup")
			}
			provider := OIDCProviderSnapshot{ARN: "arn:aws:iam::123456789012:oidc-provider/" + strings.TrimPrefix(fixture.Issuer, "https://"), ID: "provider", Version: "1", IssuerURL: fixture.Issuer, ClientIDs: []string{"client-a", "client-b"}}
			keys := OIDCKeySet{IssuerURL: fixture.Issuer, ProviderID: provider.ID, ProviderVersion: provider.Version, Keys: oidcFixtureKeys(t)}
			for _, scenario := range fixture.Scenarios {
				t.Run(scenario.Scenario, func(t *testing.T) {
					// These rows establish IAM propagation and provider-ID routing, not JWT
					// cryptographic validity. Full SDK tests exercise the routing separately.
					if strings.Contains(scenario.Error, "(AccessDenied)") || scenario.Input.ProviderId != "" {
						t.Skip("covered by trust/routing integration")
					}
					now, err := time.Parse(time.RFC3339Nano, scenario.ObservedAt)
					if err != nil {
						t.Fatal(err)
					}
					token, apiErr := parseOIDCJWT(scenario.Input.WebIdentityToken)
					keys := keys
					if len(scenario.JWKS) > 0 {
						keys.Keys = decodeOIDCFixtureKeys(t, scenario.JWKS)
					}
					var actual oidcIdentity
					if apiErr == nil {
						actual, apiErr = verifyOIDCJWT(token, provider, keys, now)
					}
					if scenario.ExitCode != 0 {
						match := regexp.MustCompile(`error occurred \(([^)]+)\)`).FindStringSubmatch(scenario.Error)
						if len(match) != 2 || apiErr == nil || apiErr.Code != match[1] {
							t.Fatalf("AWS=%s local=%v", scenario.Error, apiErr)
						}
						return
					}
					if apiErr != nil {
						t.Fatal(apiErr)
					}
					if actual.subject != scenario.Output.SubjectFromWebIdentityToken || actual.audience != scenario.Output.Audience || actual.sourceIdentity != scenario.Output.SourceIdentity {
						t.Fatalf("claims local=%+v AWS=%+v", actual, scenario.Output)
					}
					// Every successful fixture must actually fail when its signed payload is
					// changed; parsing and trusting the claims alone cannot pass this replay.
					parts := strings.Split(scenario.Input.WebIdentityToken, ".")
					raw, err := base64.RawURLEncoding.DecodeString(parts[1])
					if err != nil {
						t.Fatal(err)
					}
					raw = append(raw[:len(raw)-1], []byte(`,"tampered":true}`)...)
					parts[1] = base64.RawURLEncoding.EncodeToString(raw)
					altered, apiErr := parseOIDCJWT(strings.Join(parts, "."))
					if apiErr != nil {
						t.Fatal(apiErr)
					}
					if _, apiErr = verifyOIDCJWT(altered, provider, keys, now); apiErr == nil {
						t.Fatal("modified signed payload accepted")
					}
				})
			}
		})
	}
}
