package policy

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestOIDCTrustControlsAWSReplay(t *testing.T) {
	for _, name := range []string{"oidc_trust_controls_aws.json", "oidc_trust_controls_edges_aws.json", "oidc_trust_controls_github_aws.json", "oidc_trust_controls_details_aws.json"} {
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			CleanupComplete bool `json:"cleanup_complete"`
			Scenarios       []struct {
				Issuer, Case, Code, Message string
				Document                    json.RawMessage
			}
		}
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		if !fixture.CleanupComplete || len(fixture.Scenarios) == 0 {
			t.Fatal("fixture does not establish cleanup or behavior")
		}
		for _, row := range fixture.Scenarios {
			t.Run(name+"/"+row.Issuer+"/"+row.Case, func(t *testing.T) {
				err := ValidateOIDCTrustControls(row.Document)
				if row.Code == "" && err != nil {
					t.Fatalf("AWS accepted trust policy: %v", err)
				}
				if row.Code == "MalformedPolicyDocument" && !errors.Is(err, ErrInvalidPolicy) {
					t.Fatalf("AWS rejected trust policy (%s); local error: %v", row.Message, err)
				}
				if row.Code != "" && row.Code != "MalformedPolicyDocument" {
					t.Fatalf("unclassified AWS observation: %s", row.Code)
				}
			})
		}
	}
}

func TestOIDCTrustControlsAllOfficialProviders(t *testing.T) {
	data, err := os.ReadFile("testdata/oidc_trust_controls_source.json")
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		Source       string
		SourceSHA256 string `json:"source_sha256"`
		Providers    []struct{ Provider, Issuer, Claim string }
	}
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	if len(source.Providers) != len(sharedOIDCTrustClaims) || len(source.Providers) < 22 || len(source.SourceSHA256) != 64 || !strings.HasPrefix(source.Source, "https://docs.aws.amazon.com/") {
		t.Fatal("generated controls diverge from the pinned AWS source")
	}
	for _, row := range source.Providers {
		t.Run(row.Issuer, func(t *testing.T) {
			if sharedOIDCTrustClaims[row.Issuer] != row.Claim {
				t.Fatal("generated required claim differs from AWS table")
			}
			principal := "arn:aws:iam::123456789012:oidc-provider/" + row.Issuer
			if row.Issuer == "cognito-identity.amazonaws.com" {
				principal = row.Issuer
			}
			statement := map[string]any{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": map[string]string{"Federated": principal}}
			check := func(wantError bool) {
				data, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statement})
				if err != nil {
					t.Fatal(err)
				}
				if err := ValidateOIDCTrustControls(data); (err != nil) != wantError {
					t.Fatalf("required claim validation error=%v; wantError=%t", err, wantError)
				}
			}
			check(true)
			statement["Condition"] = map[string]any{"StringEquals": map[string]string{row.Claim: "owned-value"}}
			check(false)
			statement["Condition"] = map[string]any{"StringEqualsIfExists": map[string]string{row.Claim: "owned-value"}}
			check(true)
			delete(statement, "Condition")
			statement["Effect"] = "Deny"
			check(false)
		})
	}
}

func TestOIDCTrustControlsDoNotRevalidateStoredLegacyPolicy(t *testing.T) {
	principal := "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
	legacy := []byte(`{"Statement":{"Effect":"Allow","Principal":{"Federated":"` + principal + `"},"Action":"sts:AssumeRoleWithWebIdentity"}}`)
	if err := ValidateOIDCTrustControls(legacy); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("new write accepted legacy unrestricted trust", err)
	}
	resource, err := TrustResourcePolicy(legacy)
	if err != nil {
		t.Fatal("legacy rendering/evaluation applied write controls", err)
	}
	document, err := ParseResource(resource)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := EvaluateResource(document, Request{Action: "sts:AssumeRoleWithWebIdentity", Resource: "arn:aws:iam::123456789012:role/legacy"}, Principal{Federated: principal})
	if err != nil || decision.Decision != Allow {
		t.Fatal("legacy persisted trust stopped evaluating", decision, err)
	}
}
