package policy_test

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"stackd/iam/policy"
)

func TestAuthorizationExplainsReachedConditionsWithoutValues(t *testing.T) {
	request := policy.Request{Action: "sqs:SendMessage", Resource: "arn:aws:sqs:us-east-1:123456789012:queue", Context: map[string][]string{"sts:ExternalId": {"private-request-value"}}}
	snapshot := policy.Authorization{Principal: policy.Principal{ARN: "arn:aws:iam::123456789012:user/app", AccountID: "123456789012", Partition: "aws"}, Identity: []policy.Policy{{Source: "arn:aws:iam::123456789012:policy/send", Version: "v3", Document: `{
 "Version":"2012-10-17",
 "Statement":[
  {"Sid":"OtherAction","Effect":"Allow","Action":"sqs:ReceiveMessage","Resource":"*","Condition":{"StringEquals":{"unused":"value"}}},
  {"Sid":"OtherResource","Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:123456789012:other"},
  {"Sid":"MissingVariable","Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:123456789012:${aws:PrincipalTag/queue}"},
  {"Sid":"MissingCondition","Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"payments"}}},
  {"Sid":"WrongValue","Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"StringEquals":{"sts:ExternalId":"private-policy-value"}}}
 ]
}`}}}
	result, err := policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.ImplicitDeny || len(result.Layers) != 1 {
		t.Fatalf("authorization = %+v, %v", result, err)
	}
	p := result.Layers[0].Policies[0]
	if p.Source != snapshot.Identity[0].Source || p.Version != "v3" || p.Decision != policy.ImplicitDeny || p.Failed {
		t.Fatalf("source = %+v", p)
	}
	want := []policy.MatchOutcome{policy.ActionMismatch, policy.ResourceMismatch, policy.ResourceMismatch, policy.ConditionsMismatch, policy.ConditionsMismatch}
	if len(p.Statements) != len(want) {
		t.Fatalf("statements = %+v", p.Statements)
	}
	for i, st := range p.Statements {
		if st.StatementIndex != i || st.Outcome != want[i] || st.Start.Line == 0 || st.End.Column == 0 {
			t.Fatalf("statement %d = %+v", i, st)
		}
	}
	if len(p.Statements[0].Conditions) != 0 || !reflect.DeepEqual(p.Statements[2].MissingVariables, []string{"aws:PrincipalTag/queue"}) {
		t.Fatalf("unreached conditions or resource variable = %+v", p.Statements)
	}
	missing := p.Statements[3].Conditions[0]
	if missing.Key != "aws:PrincipalTag/team" || !missing.Missing || missing.Matched || missing.Failed {
		t.Fatalf("missing comparison = %+v", missing)
	}
	wrong := p.Statements[4].Conditions[0]
	if wrong.Missing || wrong.Matched || wrong.Failed || wrong.Operator != "StringEquals" {
		t.Fatalf("failed comparison = %+v", wrong)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-request-value", "private-policy-value"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("trace retained a private value: %s", secret)
		}
	}
	p.Statements[2].MissingVariables[0] = "caller mutation"
	again, err := policy.Authorize(request, snapshot)
	if err != nil || again.Layers[0].Policies[0].Statements[2].MissingVariables[0] != "aws:PrincipalTag/queue" {
		t.Fatalf("caller mutation changed evaluation: %+v, %v", again, err)
	}
}

func TestAuthorizationTraceRetainsFailedConditions(t *testing.T) {
	request := policy.Request{Action: "sqs:SendMessage", Resource: "*", Context: map[string][]string{"aws:PrincipalTag/pattern": {"not-an-arn"}, "aws:PrincipalArn": {"arn:aws:iam::123456789012:user/test"}}}
	snapshot := policy.Authorization{Identity: []policy.Policy{{Source: "invalid-comparison", Document: `{"Version":"2012-10-17","Statement":{"Sid":"BadComparison","Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{"ArnLike":{"aws:PrincipalArn":"${aws:PrincipalTag/pattern}"}}}}`}}}
	result, err := policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.ImplicitDeny || !result.Layers[0].Policies[0].Failed || !result.Layers[0].Policies[0].Statements[0].Conditions[0].Failed {
		t.Fatalf("invalid comparison did not fail closed: %+v, %v", result, err)
	}
	snapshot.Identity = append(snapshot.Identity, policy.Policy{Source: "explicit-deny", Version: "v2", Document: `{"Statement":{"Sid":"DenySend","Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`})
	result, err = policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.ExplicitDeny || !result.Layers[0].Policies[0].Failed || result.Layers[0].Policies[1].Statements[0].SID != "DenySend" {
		t.Fatalf("explicit denial did not retain its explanation: %+v, %v", result, err)
	}
}

func TestFailedAllowConditionPreservesDocumentGrant(t *testing.T) {
	request := policy.Request{Action: "sqs:SendMessage", Resource: "*", Context: map[string][]string{
		"aws:PrincipalArn": {"arn:aws:iam::123456789012:user/test"}, "aws:PrincipalTag/pattern": {"not-an-arn"},
	}}
	snapshot := policy.Authorization{Identity: []policy.Policy{{Source: "one-document", Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"ArnLike":{"aws:PrincipalArn":"${aws:PrincipalTag/pattern}"}}}]}`}}}
	result, err := policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.Allow || result.Layers[0].Policies[0].Decision != policy.Allow || !result.Layers[0].Policies[0].Failed {
		t.Fatalf("failed comparison invalidated independent grant or its trace: %+v, %v", result, err)
	}
}

func TestAuthorizationTraceExplainsDirectGrantAndBoundaryDeny(t *testing.T) {
	request := policy.Request{Action: "sqs:SendMessage", Resource: "arn:aws:sqs:us-east-1:123456789012:queue"}
	snapshot := policy.Authorization{
		Principal: policy.Principal{ARN: "arn:aws:iam::123456789012:user/app", AccountID: "123456789012", Partition: "aws", ID: "AIDACURRENT", HasBoundary: true},
		Resource:  []policy.Policy{{Source: request.Resource, Document: `{"Statement":{"Sid":"BoundUser","Effect":"Allow","Principal":{"AWS":"AIDACURRENT"},"Action":"sqs:SendMessage","Resource":"*"}}`}},
	}
	result, err := policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.Allow || len(result.Layers) != 3 || result.Layers[1].Layer != policy.BoundaryLayer || result.Layers[1].Decision != policy.ImplicitDeny {
		t.Fatalf("direct user grant = %+v, %v", result, err)
	}
	st := result.Layers[2].Policies[0].Statements[0]
	if st.SID != "BoundUser" || !st.PrincipalBinding.Direct || st.PrincipalBinding.Delegated || st.Outcome != policy.StatementMatched {
		t.Fatalf("principal binding = %+v", st)
	}
	snapshot.Resource[0].Document = `{"Statement":{"Sid":"BoundaryRule","Effect":"Deny","NotPrincipal":{"AWS":"AIDACURRENT"},"Action":"sqs:SendMessage","Resource":"*"}}`
	result, err = policy.Authorize(request, snapshot)
	st = result.Layers[2].Policies[0].Statements[0]
	if err != nil || result.Decision != policy.ExplicitDeny || !st.BoundaryDeny || !st.NotPrincipal || !st.PrincipalBinding.Direct {
		t.Fatalf("NotPrincipal boundary deny = %+v, %v", result, err)
	}
	snapshot.Principal.HasBoundary = false
	result, err = policy.Authorize(request, snapshot)
	st = result.Layers[1].Policies[0].Statements[0]
	if err != nil || result.Decision != policy.ImplicitDeny || st.Outcome != policy.PrincipalMismatch || st.BoundaryDeny {
		t.Fatalf("excluded principal = %+v, %v", result, err)
	}
}

func TestAuthorizationTraceKeepsControlHierarchyAndResourceOwner(t *testing.T) {
	request := policy.Request{Action: "sqs:SendMessage", Resource: "arn:aws:sqs:us-east-1:222222222222:queue", Context: map[string][]string{"aws:ResourceOrgID": {"o-owner"}}}
	full := policy.Policy{Source: "p-FullAWSAccess", Document: `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}
	resourceFull := policy.Policy{Source: "p-RCPFullAWSAccess", Document: `{"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`}
	resourceDeny := policy.Policy{Source: "p-owner-deny", Document: `{"Statement":{"Sid":"OwnerRestriction","Effect":"Deny","Principal":"*","Action":"sqs:*","Resource":"*","Condition":{"StringEquals":{"aws:ResourceOrgID":"o-owner"}}}}`}
	snapshot := policy.Authorization{
		Principal: policy.Principal{ARN: "arn:aws:iam::111111111111:user/app", AccountID: "111111111111", Partition: "aws"},
		Identity:  []policy.Policy{full}, ResourceAccountID: "222222222222",
		ServiceControls:  []policy.PolicyLevel{{TargetID: "r-caller", Documents: []policy.Policy{full}}, {TargetID: "111111111111", Documents: []policy.Policy{full}}},
		ResourceControls: []policy.PolicyLevel{{TargetID: "r-owner", Documents: []policy.Policy{resourceFull}}, {TargetID: "222222222222", Documents: []policy.Policy{resourceFull, resourceDeny}}},
	}
	result, err := policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.ExplicitDeny || len(result.Layers) != 5 {
		t.Fatalf("owner restriction = %+v, %v", result, err)
	}
	last := result.Layers[4]
	if last.Layer != policy.ResourceControlLayer || last.TargetID != "222222222222" || last.Policies[1].Source != "p-owner-deny" || !last.Policies[1].Statements[0].Conditions[0].Matched {
		t.Fatalf("owner hierarchy trace = %+v", last)
	}
	external, err := policy.AuthorizeResourceControls(request, snapshot.ResourceControls)
	if err != nil || external.Decision != result.Decision || !reflect.DeepEqual(external.Layers, result.Layers[3:]) {
		t.Fatalf("external federation restriction differs: %+v, %v", external, err)
	}
	snapshot.ServiceControls[1].Documents = nil
	result, err = policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.ImplicitDeny || len(result.Layers) != 3 || result.Layers[2].TargetID != "111111111111" {
		t.Fatalf("caller hierarchy trace = %+v, %v", result, err)
	}
}

func TestAuthorizationTraceRecordsMissingIfExistsAsMatch(t *testing.T) {
	result, err := policy.Authorize(policy.Request{Action: "sqs:SendMessage", Resource: "*"}, policy.Authorization{Identity: []policy.Policy{{Document: `{"Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{"StringEqualsIfExists":{"aws:PrincipalTag/team":"payments"}}}}`}}})
	if err != nil || result.Decision != policy.Allow {
		t.Fatalf("IfExists = %+v, %v", result, err)
	}
	condition := result.Layers[0].Policies[0].Statements[0].Conditions[0]
	if !condition.Missing || !condition.Matched {
		t.Fatalf("missing input incorrectly reported as a failed comparison: %+v", condition)
	}
}

func TestAuthorizationUsesResourceARNAccount(t *testing.T) {
	request := policy.Request{Action: "sqs:SendMessage", Resource: "arn:aws:sqs:us-east-1:222222222222:queue"}
	snapshot := policy.Authorization{
		Principal: policy.Principal{ARN: "arn:aws:iam::111111111111:user/app", AccountID: "111111111111", Partition: "aws"},
		Resource:  []policy.Policy{{Document: `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/app"},"Action":"sqs:SendMessage","Resource":"*"}}`}},
	}
	for _, override := range []string{"", "111111111111", "222222222222"} {
		snapshot.ResourceAccountID = override
		result, err := policy.Authorize(request, snapshot)
		if err != nil || result.Decision != policy.ImplicitDeny || !strings.Contains(result.Reason, "Cross-account") {
			t.Fatalf("owner override %q: %+v, %v", override, result, err)
		}
	}
	snapshot.Identity = []policy.Policy{{Document: `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}}`}}
	result, err := policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.Allow {
		t.Fatalf("cross-account permissions = %+v, %v", result, err)
	}
}

func TestAuthorizationUsesExplicitOwnerForGlobalDelegation(t *testing.T) {
	request := policy.Request{Action: "organizations:ListAccounts", Resource: "*"}
	snapshot := policy.Authorization{
		Principal: policy.Principal{ARN: "arn:aws:iam::111111111111:user/app", AccountID: "111111111111", Partition: "aws"},
		Resource:  []policy.Policy{{Document: `{"Statement":{"Effect":"Allow","Principal":"*","Action":"organizations:ListAccounts","Resource":"*"}}`}},
	}
	result, err := policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.Allow {
		t.Fatalf("same-account direct grant: %+v, %v", result, err)
	}
	snapshot.ResourceAccountID = "222222222222"
	result, err = policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.ImplicitDeny {
		t.Fatalf("delegation bypassed identity permissions: %+v, %v", result, err)
	}
	snapshot.Identity = []policy.Policy{{Document: `{"Statement":{"Effect":"Allow","Action":"organizations:ListAccounts","Resource":"*"}}`}}
	result, err = policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.Allow {
		t.Fatalf("both accounts granted access: %+v, %v", result, err)
	}
	snapshot.HasSessionPolicy = true
	result, err = policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.ImplicitDeny {
		t.Fatalf("delegation bypassed session restrictions: %+v, %v", result, err)
	}
}

func TestServiceAccountGrantPreservesPolicyRestrictionsAndTrace(t *testing.T) {
	request := policy.Request{Action: "organizations:ListAccounts", Resource: "*"}
	full := policy.Policy{Source: "member-permissions", Document: `{"Statement":{"Effect":"Allow","Action":"organizations:*","Resource":"*"}}`}
	snapshot := policy.Authorization{Principal: policy.Principal{ARN: "arn:aws:iam::222222222222:role/operator", AccountID: "222222222222", Partition: "aws"},
		ResourceAccountID: "111111111111", ResourceAccountGrant: true}
	result, err := policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.ImplicitDeny {
		t.Fatalf("service grant bypassed identity: %+v, %v", result, err)
	}
	snapshot.Identity = []policy.Policy{full}
	result, err = policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.Allow {
		t.Fatalf("account grant: %+v, %v", result, err)
	}
	layer := result.Layers[len(result.Layers)-1]
	if layer.Layer != policy.ResourceLayer || layer.Decision != policy.Allow || layer.Reason == "" || len(layer.Policies) != 0 {
		t.Fatalf("service grant has no explanation: %+v", layer)
	}
	snapshot.Resource = []policy.Policy{{Source: "organization-delegation", Document: `{"Statement":{"Effect":"Deny","Principal":"*","Action":"organizations:ListAccounts","Resource":"*"}}`}}
	result, err = policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.ExplicitDeny {
		t.Fatalf("service grant bypassed resource deny: %+v, %v", result, err)
	}
	layer = result.Layers[len(result.Layers)-1]
	if len(layer.Policies) != 1 || layer.Policies[0].Source != "organization-delegation" || layer.Policies[0].Statements[0].Outcome != policy.StatementMatched {
		t.Fatalf("resource denial lost its source: %+v", layer)
	}
	snapshot.Resource = []policy.Policy{{Source: "organization-delegation", Document: `{"Statement":{"Effect":"Deny","Principal":"*","Action":"organizations:UpdatePolicy","Resource":"*"}}`}}
	result, err = policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.Allow {
		t.Fatalf("unmatched deny removed service access: %+v, %v", result, err)
	}
	snapshot.Principal.HasBoundary = true
	result, err = policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.ImplicitDeny {
		t.Fatalf("service grant bypassed boundary: %+v, %v", result, err)
	}
	snapshot.Principal.HasBoundary = false
	snapshot.HasSessionPolicy = true
	result, err = policy.Authorize(request, snapshot)
	if err != nil || result.Decision != policy.ImplicitDeny {
		t.Fatalf("service grant bypassed session policy: %+v, %v", result, err)
	}
}

func TestServiceGrantAttribution(t *testing.T) {
	data, err := os.ReadFile("testdata/service_grant_attribution.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Request policy.Request
		Cases   []struct {
			Name                 string
			Authorization        policy.Authorization
			ServiceGrantRequired bool
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Cases {
		t.Run(row.Name, func(t *testing.T) {
			result, err := policy.Authorize(fixture.Request, row.Authorization)
			if err != nil || result.Decision != policy.Allow || result.ServiceGrantRequired != row.ServiceGrantRequired {
				t.Fatalf("authorization = %+v, %v; want Allow, service grant required %t", result, err, row.ServiceGrantRequired)
			}
		})
	}
}
