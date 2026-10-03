package policy_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"stackd/iam/policy"
)

func conditionDocument(t *testing.T, operator string, values any) *policy.Document {
	t.Helper()
	data, err := json.Marshal(map[string]any{"Statement": map[string]any{
		"Effect": "Allow", "Action": "*", "Resource": "*",
		"Condition": map[string]any{operator: map[string]any{"Example:Key": values}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return mustParse(t, string(data))
}

func TestConditionOperators(t *testing.T) {
	// These cases exercise the documented condition comparison and NOR rules:
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-logic-multiple-context-keys-or-values.html
	for _, tt := range []struct {
		name, operator string
		policyValue    any
		requestValue   []string
		want           bool
	}{
		{"string exact", "StringEquals", "prod", []string{"prod"}, true},
		{"string case mismatch", "StringEquals", "prod", []string{"Prod"}, false},
		{"string no wildcard", "StringEquals", "prod*", []string{"production"}, false},
		{"case fold", "StringEqualsIgnoreCase", "prod", []string{"PrOd"}, true},
		{"string missing", "StringEquals", "prod", nil, false},
		{"empty string exact", "StringEquals", "", []string{""}, true},
		{"string list any", "StringEquals", []string{"dev", "prod"}, []string{"prod"}, true},
		{"empty policy list", "StringEquals", []string{}, []string{"prod"}, false},
		{"empty negated policy list", "StringNotEquals", []string{}, []string{"prod"}, false},
		{"empty negated policy missing", "StringNotEquals", []string{}, nil, false},
		{"empty if exists missing", "StringNotEqualsIfExists", []string{}, nil, true},
		{"empty if exists present", "StringNotEqualsIfExists", []string{}, []string{"prod"}, false},
		{"empty all set missing", "ForAllValues:StringNotEquals", []string{}, nil, true},
		{"empty all set present", "ForAllValues:StringNotEquals", []string{}, []string{"prod"}, false},
		{"empty any set missing", "ForAnyValue:StringNotEquals", []string{}, nil, false},
		{"empty any set present", "ForAnyValue:StringNotEquals", []string{}, []string{"prod"}, false},
		{"negated string", "StringNotEquals", "prod", []string{"dev"}, true},
		{"negated string match", "StringNotEquals", "prod", []string{"prod"}, false},
		{"negated missing", "StringNotEquals", "prod", nil, true},
		{"negated list NOR denies", "StringNotEquals", []string{"dev", "prod"}, []string{"prod"}, false},
		{"negated list NOR allows", "StringNotEquals", []string{"dev", "prod"}, []string{"staging"}, true},
		{"negated fold", "StringNotEqualsIgnoreCase", "prod", []string{"PROD"}, false},
		{"like glob", "StringLike", "team-?/*", []string{"team-a/nested/path"}, true},
		{"like full match", "StringLike", "prod", []string{"production"}, false},
		{"not like list NOR", "StringNotLike", []string{"dev*", "prod*"}, []string{"production"}, false},
		{"not like mismatch", "StringNotLike", []string{"dev*", "prod*"}, []string{"staging"}, true},
		{"if exists missing", "StringEqualsIfExists", "prod", nil, true},
		{"if exists present mismatch", "StringEqualsIfExists", "prod", []string{"dev"}, false},
		{"if exists empty present", "StringEqualsIfExists", "prod", []string{""}, false},
		{"negated if exists missing", "StringNotEqualsIfExists", "prod", nil, true},
		{"numeric equals", "NumericEquals", 10, []string{"1e1"}, true},
		{"numeric exact large integer", "NumericEquals", "9007199254740993", []string{"9007199254740992"}, false},
		{"numeric decimal", "NumericEquals", "0.1", []string{"1e-1"}, true},
		{"numeric not equals", "NumericNotEquals", []int{10, 20}, []string{"20"}, false},
		{"numeric not equals missing", "NumericNotEquals", 10, nil, true},
		{"numeric less", "NumericLessThan", 10, []string{"9"}, true},
		{"numeric less boundary", "NumericLessThan", 10, []string{"10"}, false},
		{"numeric less equals", "NumericLessThanEquals", 10, []string{"10"}, true},
		{"numeric greater", "NumericGreaterThan", 10, []string{"11"}, true},
		{"numeric greater boundary", "NumericGreaterThan", 10, []string{"10"}, false},
		{"numeric greater equals", "NumericGreaterThanEquals", 10, []string{"10"}, true},
		{"numeric missing", "NumericLessThan", 10, nil, false},
		{"date exact", "DateEquals", "2025-01-01T00:00:00Z", []string{"2025-01-01T00:00:00Z"}, true},
		{"date timezone", "DateEquals", "2025-01-01T00:00:00Z", []string{"2025-01-01T01:00:00+01:00"}, true},
		{"date epoch", "DateEquals", "2025-01-01T00:00:00Z", []string{"1735689600"}, true},
		{"date fractional epoch", "DateEquals", "2025-01-01T00:00:00.123456789Z", []string{"1735689600.123456789"}, true},
		{"date negative epoch", "DateEquals", "1969-12-31T23:59:59.5Z", []string{"-0.5"}, true},
		{"date not equals", "DateNotEquals", "2025-01-01T00:00:00Z", []string{"2025-01-01T00:00:01Z"}, true},
		{"date not equals missing", "DateNotEquals", "2025-01-01T00:00:00Z", nil, true},
		{"date less", "DateLessThan", "2025-01-01T00:00:00Z", []string{"2024-12-31T23:59:59Z"}, true},
		{"date less equals", "DateLessThanEquals", "2025-01-01T00:00:00Z", []string{"2025-01-01T00:00:00Z"}, true},
		{"date greater", "DateGreaterThan", "2025-01-01T00:00:00Z", []string{"2025-01-01T00:00:01Z"}, true},
		{"date greater equals", "DateGreaterThanEquals", "2025-01-01T00:00:00Z", []string{"2025-01-01T00:00:00Z"}, true},
		{"boolean", "Bool", true, []string{"true"}, true},
		{"boolean false", "Bool", "false", []string{"false"}, true},
		{"boolean mismatch", "Bool", true, []string{"false"}, false},
		{"boolean missing", "Bool", false, nil, false},
		{"binary", "BinaryEquals", "aGVsbG8=", []string{"aGVsbG8="}, true},
		{"binary mismatch", "BinaryEquals", "aGVsbG8=", []string{"d29ybGQ="}, false},
		{"ipv4 range", "IpAddress", "192.0.2.0/24", []string{"192.0.2.42"}, true},
		{"ipv4 outside range", "IpAddress", "192.0.2.0/24", []string{"192.0.3.1"}, false},
		{"ipv4 exact", "IpAddress", "192.0.2.42", []string{"192.0.2.42"}, true},
		{"ipv6 range", "IpAddress", "2001:db8::/32", []string{"2001:db8::123"}, true},
		{"ipv6 mixed policy", "IpAddress", []string{"192.0.2.0/24", "2001:db8::/32"}, []string{"2001:db8::123"}, true},
		{"IP version mismatch", "IpAddress", "192.0.2.0/24", []string{"2001:db8::123"}, false},
		{"negative IP", "NotIpAddress", []string{"192.0.2.0/24", "198.51.100.0/24"}, []string{"198.51.100.2"}, false},
		{"negative IP missing", "NotIpAddress", "192.0.2.0/24", nil, true},
		{"ARN equals wildcard", "ArnEquals", "arn:aws:iam::*:role/team-*", []string{"arn:aws:iam::123456789012:role/team-prod"}, true},
		{"ARN like wildcard", "ArnLike", "arn:aws:iam::*:role/team-*", []string{"arn:aws:iam::123456789012:role/team-prod"}, true},
		{"ARN case sensitive", "ArnEquals", "arn:aws:iam::*:role/team-*", []string{"arn:aws:iam::123456789012:role/Team-prod"}, false},
		{"ARN resource colons", "ArnLike", "arn:aws:lambda:*:*:function:team-*", []string{"arn:aws:lambda:us-east-1:123456789012:function:team-prod:live"}, true},
		{"ARN no component spill", "ArnLike", "arn:aws:*:*:*:role/team-*", []string{"arn:aws:iam::123456789012:prefix:role/team-prod"}, false},
		{"ARN global wildcard", "ArnLike", "*", []string{"arn:aws:iam::123456789012:role/team-prod"}, true},
		{"ARN not equals", "ArnNotEquals", "arn:aws:iam::*:role/team-*", []string{"arn:aws:iam::123456789012:role/other"}, true},
		{"ARN not like", "ArnNotLike", "arn:aws:iam::*:role/team-*", []string{"arn:aws:iam::123456789012:role/team-prod"}, false},
		{"null missing", "Null", true, nil, true},
		{"null empty", "Null", true, []string{""}, false},
		{"not null present", "Null", false, []string{"prod"}, true},
		{"null present", "Null", true, []string{"prod"}, false},
		{"not null empty", "Null", false, []string{""}, true},
		{"null multivalue", "Null", false, []string{"", "prod"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc := conditionDocument(t, tt.operator, tt.policyValue)
			request := policy.Request{Action: "s3:GetObject", Resource: "*", Context: map[string][]string{"EXAMPLE:key": tt.requestValue}}
			got, err := policy.Evaluate([]*policy.Document{doc}, request)
			if err != nil || (got == policy.Allow) != tt.want {
				t.Fatalf("Evaluate() = (%v, %v), want allowed %v", got, err, tt.want)
			}
		})
	}
}

func TestConditionSetOperators(t *testing.T) {
	// The absent-key and negated-set cases are particularly significant for
	// Deny policies. These match the AWS set-operator definitions and examples:
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition_examples-multi-valued-context-keys.html
	for _, tt := range []struct {
		name, operator string
		values         []string
		want           bool
	}{
		{"all matched", "ForAllValues:StringEquals", []string{"dev", "prod"}, true},
		{"all one mismatch", "ForAllValues:StringEquals", []string{"dev", "staging"}, false},
		{"all absent", "ForAllValues:StringEquals", nil, true},
		{"all empty string", "ForAllValues:StringEquals", []string{""}, false},
		{"any one matched", "ForAnyValue:StringEquals", []string{"dev", "staging"}, true},
		{"any all mismatch", "ForAnyValue:StringEquals", []string{"qa", "staging"}, false},
		{"any absent", "ForAnyValue:StringEquals", nil, false},
		{"any empty dataset", "ForAnyValue:StringEquals", []string{""}, false},
		{"not all one matches", "ForAllValues:StringNotEquals", []string{"dev", "staging"}, false},
		{"not all none matches", "ForAllValues:StringNotEquals", []string{"qa", "staging"}, true},
		{"not all missing", "ForAllValues:StringNotEquals", nil, true},
		{"not any one mismatch", "ForAnyValue:StringNotEquals", []string{"dev", "staging"}, true},
		{"not any all match", "ForAnyValue:StringNotEquals", []string{"dev", "prod"}, false},
		{"not any missing", "ForAnyValue:StringNotEquals", nil, false},
		{"not any empty", "ForAnyValue:StringNotEquals", []string{""}, true},
		{"all ifexists missing", "ForAllValues:StringEqualsIfExists", nil, true},
		{"any ifexists missing", "ForAnyValue:StringEqualsIfExists", nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc := conditionDocument(t, tt.operator, []string{"dev", "prod"})
			got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "s3:GetObject", Resource: "*", Context: map[string][]string{"example:key": tt.values}})
			if err != nil || (got == policy.Allow) != tt.want {
				t.Fatalf("Evaluate() = (%v, %v), want allowed %v", got, err, tt.want)
			}
		})
	}
}

func TestAWSMultiConditionExample(t *testing.T) {
	// Adapted from the AWS CreateTags example: case-insensitive tag value,
	// case-sensitive aws:TagKeys membership, AND between operators and keys.
	doc := mustParse(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"ec2:CreateTags","Resource":"arn:aws:ec2:*:*:instance/*","Condition":{"StringEqualsIgnoreCase":{"aws:RequestTag/environment":["preprod","storage"]},"ForAnyValue:StringEquals":{"aws:TagKeys":"environment"}}}}`)
	for _, tt := range []struct {
		name, environment string
		tagKeys           []string
		want              bool
	}{
		{"matches", "preprod", []string{"environment"}, true},
		{"value case ignored", "PreProd", []string{"environment", "costcenter"}, true},
		{"tag key case matters", "preprod", []string{"Environment"}, false},
		{"both conditions required", "production", []string{"environment"}, false},
		{"missing tag keys", "preprod", nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "ec2:CreateTags", Resource: "arn:aws:ec2:us-east-1:123456789012:instance/i-123", Context: map[string][]string{
				"aws:RequestTag/environment": {tt.environment}, "aws:TagKeys": tt.tagKeys,
			}})
			if err != nil || (got == policy.Allow) != tt.want {
				t.Fatalf("Evaluate() = (%v, %v), want allowed %v", got, err, tt.want)
			}
		})
	}
}

func TestForAllValuesNullGuard(t *testing.T) {
	doc := mustParse(t, `{"Statement":{"Effect":"Allow","Action":"ec2:DeleteTags","Resource":"*","Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["environment","cost-center"]},"Null":{"aws:TagKeys":"false"}}}}`)
	for _, values := range [][]string{nil, {""}, {"dept"}, {"environment"}, {"environment", "cost-center"}} {
		t.Run(fmt.Sprint(values), func(t *testing.T) {
			want := len(values) > 0 && values[0] == "environment"
			got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "ec2:DeleteTags", Resource: "*", Context: map[string][]string{"aws:TagKeys": values}})
			if err != nil || (got == policy.Allow) != want {
				t.Fatalf("Evaluate() = (%v, %v), want allowed %v", got, err, want)
			}
		})
	}
}

func TestMissingNegatedIfExistsDenies(t *testing.T) {
	doc := mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"StringNotEqualsIfExists":{"s3:x-amz-server-side-encryption":"aws:kms"}}}]}`)
	got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "s3:PutObject", Resource: "arn:aws:s3:::example/file"})
	if err != nil || got != policy.ExplicitDeny {
		t.Fatalf("Evaluate() = (%v, %v), want (explicitDeny, nil)", got, err)
	}
}

func TestConversionFailurePreservesIndependentAllow(t *testing.T) {
	allow := mustParse(t, `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	for _, tt := range []struct {
		op, value string
		values    []string
	}{
		{"NumericNotEquals", "1", []string{"NaN"}},
		{"DateNotEquals", "2025-01-01T00:00:00Z", []string{"not a date"}},
		{"NotIpAddress", "192.0.2.0/24", []string{"not an IP"}},
		{"ArnNotLike", "arn:aws:iam::*:role/*", []string{"not an ARN"}},
		{"Bool", "true", []string{"yes"}},
		{"BinaryEquals", "aGVsbG8=", []string{"invalid"}},
	} {
		t.Run(tt.op, func(t *testing.T) {
			doc := conditionDocument(t, tt.op, tt.value)
			got, err := policy.Evaluate([]*policy.Document{allow, doc}, policy.Request{Action: "s3:GetObject", Resource: "*", Context: map[string][]string{"example:key": tt.values}})
			if got != policy.Allow || err != nil {
				t.Fatalf("Evaluate() = (%v, %v), want (allowed, nil)", got, err)
			}
		})
	}
}
