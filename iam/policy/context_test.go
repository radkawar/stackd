package policy_test

import (
	"errors"
	"testing"

	"stackd/iam/policy"
)

func TestDeclaredContextCardinality(t *testing.T) {
	doc := conditionDocument(t, "StringEquals", "team")
	request := policy.Request{Action: "iam:TagUser", Resource: "*", Context: map[string][]string{"Example:Key": {"team"}}, ContextTypes: map[string]string{"EXAMPLE:key": "stringList"}}
	got, err := policy.Evaluate([]*policy.Document{doc}, request)
	if err != nil || got != policy.ImplicitDeny {
		t.Fatalf("one list value matched a scalar operator: %s, %v", got, err)
	}
	request.ContextTypes["EXAMPLE:key"] = "string"
	got, err = policy.Evaluate([]*policy.Document{doc}, request)
	if err != nil || got != policy.Allow {
		t.Fatalf("scalar value did not match: %s, %v", got, err)
	}
	request.Context["Example:Key"] = []string{"team", "env"}
	got, err = policy.Evaluate([]*policy.Document{doc}, request)
	if !errors.Is(err, policy.ErrInvalidRequest) || got != policy.ImplicitDeny {
		t.Fatalf("multiple values accepted for declared scalar: %s, %v", got, err)
	}
}

func TestInvalidContextTypeDeclarations(t *testing.T) {
	doc := mustParse(t, `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	for _, types := range []map[string]string{{"key": "unknown"}, {"": "string"}, {"key": "string", "KEY": "stringList"}} {
		got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "iam:TagUser", Resource: "*", ContextTypes: types})
		if !errors.Is(err, policy.ErrInvalidRequest) || got != policy.ImplicitDeny {
			t.Fatalf("invalid types %v: %s, %v", types, got, err)
		}
	}
}
