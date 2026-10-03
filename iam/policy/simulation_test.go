package policy_test

import (
	"errors"
	"reflect"
	"testing"

	"stackd/iam/policy"
)

func TestSimulationParsingAndResourcePatterns(t *testing.T) {
	data := []byte(`{"Id":"café","Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":["arn:aws:s3","arn:aws:s3:::example/${aws:username, 'x'}"]},{"Effect":"Deny","Action":"*","NotResource":"*"}]}`)
	if _, err := policy.Parse(data); !errors.Is(err, policy.ErrInvalidPolicy) {
		t.Fatalf("ordinary Parse changed its Id validation: %v", err)
	}
	document, err := policy.ParseSimulation(data)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	want := []string{"arn:aws:s3", "arn:aws:s3:::example/${aws:username, 'x'}", "*"}
	got := document.ResourcePatterns()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("patterns = %q; want %q", got, want)
	}
	got[0] = "modified"
	if !reflect.DeepEqual(document.ResourcePatterns(), want) {
		t.Fatal("caller mutated original resource patterns")
	}
	var absent *policy.Document
	if len(absent.ResourcePatterns()) != 0 {
		t.Fatal("nil document has patterns")
	}
}

func TestSimulationResourceTypedContextAndInvalidStates(t *testing.T) {
	document, err := policy.ParseResource([]byte(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"test:key":"yes"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	principal := policy.Principal{ARN: "arn:aws:iam::123456789012:user/alice", AccountID: "123456789012", Partition: "aws"}
	request := policy.Request{Action: "s3:GetObject", Resource: "*", Context: map[string][]string{"test:key": {"yes"}}, ContextTypes: map[string]string{"test:key": "stringList"}}
	got, err := policy.EvaluateResourceSimulationDetailed(document, request, principal)
	if err != nil || got.Decision != policy.ImplicitDeny {
		t.Fatalf("scalar condition matched a declared list: %+v, %v", got, err)
	}
	request.ContextTypes["test:key"] = "string"
	got, err = policy.EvaluateResourceSimulationDetailed(document, request, principal)
	if err != nil || got.Decision != policy.Allow || !got.Direct || len(got.MatchedStatements) != 1 {
		t.Fatalf("typed direct resource grant = %+v, %v", got, err)
	}
	if got, err := policy.EvaluateResourceDetailed(document, request, principal); err != nil || got.Decision != policy.Allow {
		t.Fatalf("ordinary resource authorization did not honor scalar types: %+v, %v", got, err)
	}
	for _, invalid := range []*policy.Document{nil, {}, mustParse(t, `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)} {
		if got, err := policy.EvaluateResourceSimulationDetailed(invalid, request, principal); !errors.Is(err, policy.ErrInvalidPolicy) || got.Decision != policy.ImplicitDeny {
			t.Fatalf("invalid resource document = %+v, %v", got, err)
		}
	}
}

func TestMissingSimulationContextIncludesAllowedLayersAndDefaults(t *testing.T) {
	identity := mustParse(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::example/${aws:PrincipalTag/team, 'fallback'}","Condition":{"StringEquals":{"aws:PrincipalAccount":"123456789012","s3express:SessionMode":"ReadOnly"}}}]}`)
	boundary := mustParse(t, `{"Statement":{"Effect":"Allow","Action":"s3:PutObject","Resource":"*","Condition":{"Bool":{"test:required":"true"}}}}`)
	request := policy.Request{Action: "s3:GetObject", Resource: "*", Context: map[string][]string{"aws:PrincipalAccount": {"123456789012"}}}
	result, err := policy.EvaluateSimulationDetailed([]*policy.Document{identity}, request)
	if err != nil || result.Decision != policy.Allow || len(result.MissingContextValues) != 0 {
		t.Fatalf("allowed identity layer = %+v, %v", result, err)
	}
	want := []string{"aws:PrincipalAccount", "aws:PrincipalTag/team", "s3express:SessionMode"}
	got := policy.MissingSimulationContextValues([]*policy.Document{identity, boundary}, map[string][]string{"TEST:REQUIRED": {"false"}})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("composed diagnostics = %q; want %q", got, want)
	}
	got[0] = "mutated"
	again := policy.MissingSimulationContextValues([]*policy.Document{nil, identity, boundary}, map[string][]string{"TEST:REQUIRED": {"false"}, "AWS:PRINCIPALACCOUNT": {"123456789012"}})
	if !reflect.DeepEqual(again, want[1:]) {
		t.Fatalf("explicit default override = %q; want %q", again, want[1:])
	}
}
