package policy_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"stackd/iam/policy"
)

func variableDocument(t *testing.T, resource string, condition any) *policy.Document {
	t.Helper()
	statement := map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": resource}
	if condition != nil {
		statement["Condition"] = condition
	}
	data, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statement})
	if err != nil {
		t.Fatal(err)
	}
	return mustParse(t, string(data))
}
func TestResourceVariablesAndLiteralWildcards(t *testing.T) {
	for _, tt := range []struct {
		name, pattern, resource string
		values                  map[string][]string
		want                    policy.Decision
	}{
		{"username", "arn:aws:s3:::example/${aws:username}/*", "arn:aws:s3:::example/alice/file", map[string][]string{"AWS:UserName": {"alice"}}, policy.Allow},
		{"different username", "arn:aws:s3:::example/${aws:username}/*", "arn:aws:s3:::example/bob/file", map[string][]string{"aws:username": {"alice"}}, policy.ImplicitDeny},
		{"missing", "arn:aws:s3:::example/${aws:username}/*", "arn:aws:s3:::example//file", nil, policy.ImplicitDeny},
		{"literal star from context", "arn:aws:s3:::example/${aws:PrincipalTag/team}/*", "arn:aws:s3:::example/other/file", map[string][]string{"aws:PrincipalTag/team": {"*"}}, policy.ImplicitDeny},
		{"literal star matches", "arn:aws:s3:::example/${aws:PrincipalTag/team}/*", "arn:aws:s3:::example/*/file", map[string][]string{"aws:PrincipalTag/team": {"*"}}, policy.Allow},
		{"literal question from context", "arn:aws:s3:::example/${aws:PrincipalTag/team}", "arn:aws:s3:::example/x", map[string][]string{"aws:PrincipalTag/team": {"?"}}, policy.ImplicitDeny},
		{"special star", "arn:aws:s3:::example/${*}", "arn:aws:s3:::example/*", nil, policy.Allow},
		{"special question", "arn:aws:s3:::example/${?}", "arn:aws:s3:::example/?", nil, policy.Allow},
		{"special question not wildcard", "arn:aws:s3:::example/${?}", "arn:aws:s3:::example/x", nil, policy.ImplicitDeny},
		{"special dollar no recursive expansion", "arn:aws:s3:::example/${$}{aws:username}", "arn:aws:s3:::example/${aws:username}", nil, policy.Allow},
		{"context no recursive expansion", "arn:aws:s3:::example/${aws:PrincipalTag/team}", "arn:aws:s3:::example/${aws:username}", map[string][]string{"aws:PrincipalTag/team": {"${aws:username}"}, "aws:username": {"alice"}}, policy.Allow},
		{"default missing", "arn:aws:s3:::example/${aws:PrincipalTag/team, 'shared'}/*", "arn:aws:s3:::example/shared/file", nil, policy.Allow},
		{"default overridden", "arn:aws:s3:::example/${aws:PrincipalTag/team, 'shared'}/*", "arn:aws:s3:::example/team/file", map[string][]string{"aws:PrincipalTag/team": {"team"}}, policy.Allow},
		{"empty does not use default", "arn:aws:s3:::example/${aws:PrincipalTag/team, 'shared'}/*", "arn:aws:s3:::example/shared/file", map[string][]string{"aws:PrincipalTag/team": {""}}, policy.ImplicitDeny},
		{"default star literal", "arn:aws:s3:::example/${aws:PrincipalTag/team, '*'}", "arn:aws:s3:::example/file", nil, policy.ImplicitDeny},
		{"default with comma", "arn:aws:s3:::example/${aws:PrincipalTag/team, 'red,blue'}", "arn:aws:s3:::example/red,blue", nil, policy.Allow},
		{"private Unicode literal", "arn:aws:s3:::example/${aws:PrincipalTag/team}", "arn:aws:s3:::example/\ue000*", map[string][]string{"aws:PrincipalTag/team": {"\ue000*"}}, policy.Allow},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc := variableDocument(t, tt.pattern, nil)
			got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "s3:GetObject", Resource: tt.resource, Context: tt.values})
			if err != nil || got != tt.want {
				t.Fatalf("decision=%s err=%v, want %s", got, err, tt.want)
			}
		})
	}
}
func TestMissingNotResourceVariableAndAlternatives(t *testing.T) {
	doc := mustParse(t, `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","NotResource":["arn:aws:s3:::example/${aws:username}/*","arn:aws:s3:::example/shared/*"]}}`)
	for _, tt := range []struct {
		resource string
		want     policy.Decision
	}{{"arn:aws:s3:::example/other/file", policy.ExplicitDeny}, {"arn:aws:s3:::example/shared/file", policy.ImplicitDeny}} {
		got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "s3:GetObject", Resource: tt.resource})
		if err != nil || got != tt.want {
			t.Fatalf("%s: %s %v", tt.resource, got, err)
		}
	}
}
func TestVariableVersionGating(t *testing.T) {
	for _, version := range []string{"", `"Version":"2008-10-17",`} {
		doc := mustParse(t, `{`+version+`"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/${aws:username}/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/owner":"${aws:username}"}}}}`)
		for _, tt := range []struct {
			resource, value string
			want            policy.Decision
		}{{"arn:aws:s3:::example/${aws:username}/file", "${aws:username}", policy.Allow}, {"arn:aws:s3:::example/alice/file", "alice", policy.ImplicitDeny}} {
			got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "s3:GetObject", Resource: tt.resource, Context: map[string][]string{"s3:ExistingObjectTag/owner": {tt.value}, "aws:username": {"alice"}}})
			if err != nil || got != tt.want {
				t.Fatalf("version=%q result=%s err=%v", version, got, err)
			}
		}
	}
}
func TestConditionVariableOperatorsAndMissingValues(t *testing.T) {
	for _, tt := range []struct {
		name, operator, pattern, actual string
		context                         map[string][]string
		want                            policy.Decision
	}{
		{"equals", "StringEquals", "${aws:PrincipalTag/team}", "red", map[string][]string{"aws:PrincipalTag/team": {"red"}}, policy.Allow},
		{"equals fold", "StringEqualsIgnoreCase", "${aws:PrincipalTag/team}", "RED", map[string][]string{"aws:PrincipalTag/team": {"red"}}, policy.Allow},
		{"like literal insertion", "StringLike", "prefix-${aws:PrincipalTag/team}-*", "prefix-red-end", map[string][]string{"aws:PrincipalTag/team": {"red"}}, policy.Allow},
		{"no wildcard injection", "StringLike", "prefix-${aws:PrincipalTag/team}", "prefix-any", map[string][]string{"aws:PrincipalTag/team": {"*"}}, policy.ImplicitDeny},
		{"missing positive", "StringEquals", "${aws:PrincipalTag/team}", "", nil, policy.ImplicitDeny},
		{"missing negated", "StringNotLike", "${aws:PrincipalTag/team}", "anything", nil, policy.Allow},
		{"missing embedded positive", "StringLike", "prefix-${aws:PrincipalTag/team}", "prefix-", nil, policy.ImplicitDeny},
		{"missing embedded negated", "StringNotEquals", "prefix-${aws:PrincipalTag/team}", "prefix-", nil, policy.Allow},
		{"whole arn", "ArnEquals", "${aws:PrincipalTag/team}", "arn:aws:s3:::example/file", map[string][]string{"aws:PrincipalTag/team": {"arn:aws:s3:::example/file"}}, policy.Allow},
		{"arn resource component", "ArnLike", "arn:aws:s3:::example/${aws:PrincipalTag/team}/*", "arn:aws:s3:::example/red/file", map[string][]string{"aws:PrincipalTag/team": {"red"}}, policy.Allow},
		{"arn literal star", "ArnLike", "arn:aws:s3:::example/${aws:PrincipalTag/team}/*", "arn:aws:s3:::example/other/file", map[string][]string{"aws:PrincipalTag/team": {"*"}}, policy.ImplicitDeny},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc := variableDocument(t, "*", map[string]any{tt.operator: map[string]string{"s3:ExistingObjectTag/owner": tt.pattern}})
			context := map[string][]string{"s3:ExistingObjectTag/owner": {tt.actual}}
			for k, v := range tt.context {
				context[k] = v
			}
			got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::example/file", Context: context})
			if err != nil || got != tt.want {
				t.Fatalf("%s %v, want %s", got, err, tt.want)
			}
		})
	}
}
func TestVariableSyntaxAndPositions(t *testing.T) {
	for _, resource := range []string{"arn:aws:s3:::example/${}", "arn:aws:s3:::example/${aws:username", "arn:aws:s3:::example/${aws:username, fallback}", "arn:aws:s3:::example/${aws:username, 'fall'back'}"} {
		data, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": map[string]string{"Effect": "Allow", "Action": "s3:GetObject", "Resource": resource}})
		if _, err := policy.Parse(data); !errors.Is(err, policy.ErrInvalidPolicy) {
			t.Fatalf("resource=%q err=%v", resource, err)
		}
	}
	for _, op := range []string{"NumericEquals", "DateEquals", "Bool", "BinaryEquals", "IpAddress", "Null"} {
		data, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": map[string]any{"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": map[string]any{op: map[string]string{"aws:SecureTransport": "${aws:PrincipalTag/value}"}}}})
		if _, err := policy.Parse(data); !errors.Is(err, policy.ErrInvalidPolicy) {
			t.Fatalf("op=%s err=%v", op, err)
		}
	}
}
func TestMultivaluedVariablesDoNotExpandAndDocumentsRemainImmutable(t *testing.T) {
	doc := variableDocument(t, "arn:aws:s3:::example/${aws:PrincipalTag/team}/*", nil)
	decision, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::example/red/file", Context: map[string][]string{"aws:PrincipalTag/team": {"red", "blue"}}})
	if decision != policy.ImplicitDeny || err != nil {
		t.Fatalf("multivalued result=%s err=%v", decision, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			name := fmt.Sprintf("team%d", i)
			decision, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::example/" + name + "/file", Context: map[string][]string{"aws:PrincipalTag/team": {name}}})
			if err != nil || decision != policy.Allow {
				t.Errorf("concurrent decision=%s err=%v", decision, err)
			}
		})
	}
	wg.Wait()
}
func TestResourceAndTrustPolicyVariables(t *testing.T) {
	data := []byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/${aws:PrincipalTag/team}/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/owner":"${aws:username}"}}}}`)
	doc, err := policy.ParseResource(data)
	if err != nil {
		t.Fatal(err)
	}
	result, err := policy.EvaluateResource(doc, policy.Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::example/red/file", Context: map[string][]string{"aws:PrincipalTag/team": {"red"}, "aws:username": {"alice"}, "s3:ExistingObjectTag/owner": {"alice"}}}, policy.Principal{ARN: "arn:aws:iam::111111111111:user/alice", AccountID: "111111111111", Partition: "aws"})
	if err != nil || result.Decision != policy.Allow || !result.Direct {
		t.Fatalf("resource policy=%v err=%v", result, err)
	}
	trust, err := policy.TrustResourcePolicy([]byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:RoleSessionName":"${aws:username}"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	doc, err = policy.ParseResource(trust)
	if err != nil {
		t.Fatal(err)
	}
	result, err = policy.EvaluateResource(doc, policy.Request{Action: "sts:AssumeRole", Resource: "arn:aws:iam::111111111111:role/Role", Context: map[string][]string{"sts:RoleSessionName": {"alice"}, "aws:username": {"alice"}}}, policy.Principal{ARN: "arn:aws:iam::111111111111:user/alice", AccountID: "111111111111", Partition: "aws"})
	if err != nil || result.Decision != policy.Allow {
		t.Fatalf("trust=%v err=%v", result, err)
	}
}
