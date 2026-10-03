package policy_test

import (
	"encoding/json"
	"testing"

	"stackd/iam/policy"
)

func TestFederatedTrustPrincipalSelection(t *testing.T) {
	provider := "arn:aws:iam::123456789012:saml-provider/corporate"
	for _, principal := range []string{`{"Federated":"` + provider + `"}`, `{"AWS":"*"}`, `{"AWS":"arn:aws:iam::123456789012:root"}`, `{"Federated":"arn:aws:iam::123456789012:saml-provider/other"}`} {
		trust := `{"Statement":{"Effect":"Allow","Principal":` + principal + `,"Action":"sts:AssumeRoleWithSAML"}}`
		converted, err := policy.TrustResourcePolicy([]byte(trust))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := policy.ParseResource(converted)
		if err != nil {
			t.Fatal(err)
		}
		decision, err := policy.EvaluateResource(doc, policy.Request{Action: "sts:AssumeRoleWithSAML", Resource: "arn:aws:iam::123456789012:role/work"}, policy.Principal{Federated: provider, Partition: "aws"})
		expected := policy.ImplicitDeny
		if principal == `{"Federated":"`+provider+`"}` {
			expected = policy.Allow
		}
		if err != nil || decision.Decision != expected {
			t.Fatalf("principal %s: %v, %v", principal, decision, err)
		}
	}
	for _, principal := range []string{`"*"`, `{"Federated":"*"}`, `{"Federated":"arn:aws:iam::123456789012:user/user"}`} {
		if _, err := policy.TrustResourcePolicy([]byte(`{"Statement":{"Effect":"Allow","Principal":` + principal + `,"Action":"sts:AssumeRole"}}`)); err == nil {
			t.Fatalf("invalid trust accepted: %s", principal)
		}
	}
}

func TestFederatedPrincipalCannotAuthorizeAWSCredentials(t *testing.T) {
	for _, provider := range []string{"accounts.google.com", "cognito-identity.amazonaws.com", "www.amazon.com", "graph.facebook.com", "arn:aws:iam::123456789012:oidc-provider/idp.example/path"} {
		reference, _ := json.Marshal(provider)
		converted, err := policy.TrustResourcePolicy([]byte(`{"Statement":{"Effect":"Allow","Principal":{"Federated":` + string(reference) + `},"Action":"sts:*"}}`))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := policy.ParseResource(converted)
		if err != nil {
			t.Fatal(err)
		}
		for _, principal := range []policy.Principal{{ARN: provider, ID: provider, AccountID: "123456789012", Partition: "aws"}, {Service: provider, Partition: "aws"}} {
			decision, err := policy.EvaluateResource(doc, policy.Request{Action: "sts:AssumeRole", Resource: "arn:aws:iam::123456789012:role/work"}, principal)
			if err != nil || decision.Decision != policy.ImplicitDeny {
				t.Fatalf("external trust authorized an AWS/service principal: %v, %v", decision, err)
			}
		}
	}
}
