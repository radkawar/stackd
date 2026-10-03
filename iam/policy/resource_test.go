package policy_test

import (
	"strings"
	"testing"

	"stackd/iam/policy"
)

func TestResourcePrincipalSelectors(t *testing.T) {
	caller := policy.Principal{ARN: "arn:aws:iam::123456789012:user/app", AccountID: "123456789012", Partition: "aws", ID: "AIDAEXAMPLE"}
	request := policy.Request{Action: "sqs:SendMessage", Resource: "arn:aws:sqs:us-east-1:123456789012:work"}
	for _, tc := range []struct {
		principal         string
		direct, delegated bool
	}{
		{`"*"`, true, false},
		{`{"AWS":"123456789012"}`, false, true},
		{`{"AWS":"arn:aws:iam::123456789012:root"}`, false, true},
		{`{"AWS":"arn:aws-cn:iam::123456789012:root"}`, false, false},
		{`{"AWS":"arn:aws:iam::123456789012:user/app"}`, true, false},
		{`{"AWS":"arn:aws:iam::123456789012:user/App"}`, false, false},
		{`{"AWS":["AIDAEXAMPLE","999999999999"]}`, true, false},
		{`{"Service":"sns.amazonaws.com"}`, false, false},
	} {
		doc, err := policy.ParseResource([]byte(`{"Id":"queue-policy","Statement":{"Sid":"Key administrator permissions","Effect":"Allow","Principal":` + tc.principal + `,"Action":"sqs:*","Resource":"*"}}`))
		if err != nil {
			t.Fatal(err)
		}
		out, err := policy.EvaluateResource(doc, request, caller)
		if err != nil || out.Direct != tc.direct || out.Delegated != tc.delegated || (out.Decision == policy.Allow) != (tc.direct || tc.delegated) {
			t.Fatalf("principal %s result %+v err %v", tc.principal, out, err)
		}
		if decision, err := policy.Evaluate([]*policy.Document{doc}, request); err == nil || decision != policy.ImplicitDeny {
			t.Fatal("resource policy accepted as identity policy")
		}
	}
}

func TestRejectInvalidResourcePolicies(t *testing.T) {
	base := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"sqs:*","Resource":"*"}}`
	cases := []string{
		strings.Replace(base, `"Principal":{"AWS":"123456789012"},`, "", 1),
		strings.Replace(base, `"Principal"`, `"NotPrincipal"`, 1),
		strings.Replace(base, `"123456789012"`, `"arn:aws:iam::123456789012:user/*"`, 1),
		strings.Replace(base, `"123456789012"`, `[]`, 1),
		strings.Replace(base, `"Effect":"Allow"`, `"Effect":"Allow","Effect":"Deny"`, 1),
		strings.Replace(base, `"Principal":{"AWS":"123456789012"}`, `"Principal":123`, 1),
	}
	for _, input := range cases {
		if _, err := policy.ParseResource([]byte(input)); err == nil {
			t.Fatalf("accepted invalid policy %s", input)
		}
	}
}

func TestServiceAliasesShareOnePrincipalDecision(t *testing.T) {
	const canonical = "logs.amazonaws.com"
	const regional = "logs.us-east-1.amazonaws.com"
	principal := policy.Principal{Service: canonical, ServiceAliases: []string{regional}, Partition: "aws"}
	request := policy.Request{Action: "lambda:InvokeFunction", Resource: "arn:aws:lambda:us-east-1:123456789012:function:target"}
	grant := func(name string) string {
		return `{"Statement":{"Effect":"Allow","Principal":{"Service":"` + name + `"},"Action":"lambda:InvokeFunction","Resource":"*"}}`
	}
	deny := func(selector, name string) string {
		return `{"Statement":{"Effect":"Deny","` + selector + `":{"Service":"` + name + `"},"Action":"lambda:InvokeFunction","Resource":"*"}}`
	}
	for _, tc := range []struct {
		name, allow, deny string
		want              policy.Decision
	}{
		{"canonical grant", canonical, "", policy.Allow},
		{"regional grant", regional, "", policy.Allow},
		{"other region", "logs.us-west-2.amazonaws.com", "", policy.ImplicitDeny},
		{"regional denial overrides canonical grant", canonical, deny("Principal", regional), policy.ExplicitDeny},
		{"canonical denial overrides regional grant", regional, deny("Principal", canonical), policy.ExplicitDeny},
		{"regional NotPrincipal exclusion", canonical, deny("NotPrincipal", regional), policy.Allow},
		{"canonical NotPrincipal exclusion", regional, deny("NotPrincipal", canonical), policy.Allow},
		{"unrelated NotPrincipal exclusion denies", regional, deny("NotPrincipal", "logs.us-west-2.amazonaws.com"), policy.ExplicitDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			documents := []policy.Policy{{Document: grant(tc.allow)}}
			if tc.deny != "" {
				documents = append(documents, policy.Policy{Document: tc.deny})
			}
			got, err := policy.Authorize(request, policy.Authorization{Principal: principal, Resource: documents})
			if err != nil || got.Decision != tc.want {
				t.Fatalf("decision = %v, want %v; error = %v", got.Decision, tc.want, err)
			}
		})
	}
}
