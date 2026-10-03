package policy_test

import (
	"errors"
	"testing"

	"stackd/iam/policy"
)

func TestConditionsMatchStatementBoundary(t *testing.T) {
	doc, err := policy.ParseResource([]byte(`{"Statement":[
		{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*"},
		{"Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::other/*","Condition":{"Bool":{"aws:SecureTransport":"true"}}},
		{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	request := policy.Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::bucket/key", Context: map[string][]string{"AWS:SecureTransport": {"true"}}}
	for index, want := range []bool{true, true, false} {
		got, err := doc.ConditionsMatch(index, request)
		if err != nil || got != want {
			t.Fatalf("statement %d: got %v, %v; want %v", index, got, err, want)
		}
	}
}

func TestConditionsMatchEffect(t *testing.T) {
	doc := mustParse(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"ArnEquals":{"aws:SourceArn":"${aws:PrincipalTag/arn}"}}},
		{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"ArnEquals":{"aws:SourceArn":"${aws:PrincipalTag/arn}"}}}
	]}`)
	for _, value := range []string{"arn:aws:s3:::bucket", "malformed"} {
		request := policy.Request{Action: "s3:GetObject", Resource: "*", Context: map[string][]string{"aws:SourceArn": {value}, "aws:PrincipalTag/arn": {"malformed"}}}
		for index := range 2 {
			want := index == 1 && value == "arn:aws:s3:::bucket"
			got, err := doc.ConditionsMatch(index, request)
			if err != nil || got != want {
				t.Fatalf("statement %d, ARN %q: got %v, %v; want %v", index, value, got, err, want)
			}
		}
	}
}

func TestConditionsMatchPresenceAndCardinality(t *testing.T) {
	for _, tc := range []struct {
		name, operator, operand string
		values                  []string
		kind                    string
		want                    bool
	}{
		{"missing", "Bool", "true", nil, "", false},
		{"missing if exists", "BoolIfExists", "true", nil, "", true},
		{"present if exists mismatch", "BoolIfExists", "true", []string{"false"}, "", false},
		{"null missing", "Null", "true", nil, "", true},
		{"null empty present", "Null", "true", []string{}, "", false},
		{"not null empty present", "Null", "false", []string{}, "", true},
		{"inferred list scalar operator", "Bool", "true", []string{"true", "false"}, "", false},
		{"declared singleton list scalar operator", "Bool", "true", []string{"true"}, "booleanList", false},
		{"declared singleton list set operator", "ForAnyValue:Bool", "true", []string{"true"}, "booleanList", true},
		{"ordinary unconverted numeric negation", "NumericNotEquals", "1", []string{"invalid"}, "numeric", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := conditionDocument(t, tc.operator, tc.operand)
			request := policy.Request{Action: "s3:GetObject", Resource: "*", Context: map[string][]string{"example:key": tc.values}}
			if tc.kind != "" {
				request.ContextTypes = map[string]string{"EXAMPLE:KEY": tc.kind}
			}
			got, err := doc.ConditionsMatch(0, request)
			if err != nil || got != tc.want {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestConditionsMatchVariables(t *testing.T) {
	doc := mustParse(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"s3:prefix":"home/${aws:username}"}}}}`)
	for _, tc := range []struct {
		name     string
		username []string
		want     bool
	}{
		{"expanded", []string{"alice"}, true},
		{"mismatch", []string{"bob"}, false},
		{"missing", nil, false},
		{"ambiguous", []string{"alice", "bob"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := policy.Request{Action: "s3:ListBucket", Resource: "*", Context: map[string][]string{"s3:prefix": {"home/alice"}, "AWS:UserName": tc.username}}
			got, err := doc.ConditionsMatch(0, request)
			if err != nil || got != tc.want {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestConditionsMatchInvalidRequest(t *testing.T) {
	doc := mustParse(t, `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	valid := policy.Request{Action: "s3:GetObject", Resource: "*"}
	for _, tc := range []struct {
		name    string
		doc     *policy.Document
		index   int
		request policy.Request
	}{
		{"nil document", nil, 0, valid},
		{"zero document", &policy.Document{}, 0, valid},
		{"negative index", doc, -1, valid},
		{"past end", doc, 1, valid},
		{"invalid action", doc, 0, policy.Request{Action: "s3:*", Resource: "*"}},
		{"invalid resource", doc, 0, policy.Request{Action: "s3:GetObject", Resource: "bucket"}},
		{"empty context key", doc, 0, policy.Request{Action: valid.Action, Resource: valid.Resource, Context: map[string][]string{"": {"x"}}}},
		{"colliding context keys", doc, 0, policy.Request{Action: valid.Action, Resource: valid.Resource, Context: map[string][]string{"Key": {"x"}, "key": {"x"}}}},
		{"invalid context type", doc, 0, policy.Request{Action: valid.Action, Resource: valid.Resource, ContextTypes: map[string]string{"key": "unknown"}}},
		{"colliding type keys", doc, 0, policy.Request{Action: valid.Action, Resource: valid.Resource, ContextTypes: map[string]string{"Key": "string", "key": "string"}}},
		{"scalar cardinality", doc, 0, policy.Request{Action: valid.Action, Resource: valid.Resource, Context: map[string][]string{"key": {"a", "b"}}, ContextTypes: map[string]string{"key": "string"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.doc.ConditionsMatch(tc.index, tc.request)
			if got || !errors.Is(err, policy.ErrInvalidRequest) || err == policy.ErrInvalidRequest {
				t.Fatalf("got %v, %v; want false and wrapped ErrInvalidRequest", got, err)
			}
		})
	}
}
