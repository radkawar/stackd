package policy_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"stackd/iam/policy"
)

func mustParse(t *testing.T, input string) *policy.Document {
	t.Helper()
	doc, err := policy.Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return doc
}

func TestEvaluateIdentityPolicies(t *testing.T) {
	// AWS identity policy evaluation is a union, with any explicit deny winning:
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
	read := mustParse(t, `{"Version":"2012-10-17","Statement":{"Sid":"Read","Effect":"Allow","Action":["s3:Get*","s3:ListBucket"],"Resource":["arn:aws:s3:::example","arn:aws:s3:::example/*"]}}`)
	protect := mustParse(t, `{"Statement":{"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::example/private/*"}}`)
	write := mustParse(t, `{"Statement":{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::example/*"}}`)
	for _, tt := range []struct {
		name      string
		documents []*policy.Document
		action    string
		resource  string
		want      policy.Decision
	}{
		{"union read", []*policy.Document{read, write}, "s3:GetObject", "arn:aws:s3:::example/file", policy.Allow},
		{"union write", []*policy.Document{read, write}, "s3:PutObject", "arn:aws:s3:::example/file", policy.Allow},
		{"deny after allow", []*policy.Document{read, protect}, "s3:GetObject", "arn:aws:s3:::example/private/file", policy.ExplicitDeny},
		{"deny before allow", []*policy.Document{protect, read}, "s3:GetObject", "arn:aws:s3:::example/private/file", policy.ExplicitDeny},
		{"implicit deny action", []*policy.Document{read}, "s3:DeleteObject", "arn:aws:s3:::example/file", policy.ImplicitDeny},
		{"implicit deny resource", []*policy.Document{read}, "s3:GetObject", "arn:aws:s3:::other/file", policy.ImplicitDeny},
		{"action case insensitive", []*policy.Document{read}, "S3:gEtObJeCt", "arn:aws:s3:::example/file", policy.Allow},
		{"resource case sensitive", []*policy.Document{read}, "s3:GetObject", "arn:aws:s3:::Example/file", policy.ImplicitDeny},
		{"no documents", nil, "s3:GetObject", "arn:aws:s3:::example/file", policy.ImplicitDeny},
		{"zero document", []*policy.Document{{}}, "s3:GetObject", "arn:aws:s3:::example/file", policy.ImplicitDeny},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := policy.Evaluate(tt.documents, policy.Request{Action: tt.action, Resource: tt.resource})
			if err != nil || got != tt.want {
				t.Fatalf("Evaluate() = (%v, %v), want (%v, nil)", got, err, tt.want)
			}
		})
	}
}

func TestEvaluateNotActionAndNotResource(t *testing.T) {
	doc := mustParse(t, `{"Statement":[{"Effect":"Allow","NotAction":["iam:*","organizations:*"],"Resource":"*"},{"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::allowed","arn:aws:s3:::allowed/*"]}]}`)
	for _, tt := range []struct {
		action, resource string
		want             policy.Decision
	}{
		{"s3:GetObject", "arn:aws:s3:::allowed/file", policy.Allow},
		{"s3:GetObject", "arn:aws:s3:::other/file", policy.ExplicitDeny},
		{"iam:CreateUser", "arn:aws:iam::123456789012:user/Alice", policy.ImplicitDeny},
		{"organizations:DescribeOrganization", "*", policy.ImplicitDeny},
		{"ec2:DescribeInstances", "*", policy.Allow},
	} {
		t.Run(tt.action+tt.resource, func(t *testing.T) {
			got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: tt.action, Resource: tt.resource})
			if err != nil || got != tt.want {
				t.Fatalf("Evaluate() = (%v, %v), want (%v, nil)", got, err, tt.want)
			}
		})
	}
}

func TestResourcePatterns(t *testing.T) {
	// Resource wildcard semantics differ from filesystem globbing and ARN
	// condition matching. Missing resource ARN fields are completed with *.
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
	for _, tt := range []struct {
		name, pattern, resource string
		allowed                 bool
	}{
		{"nested slashes", "arn:aws:s3:::example/*/test/*", "arn:aws:s3:::example/1/2/test/3/file", true},
		{"empty slash segments", "arn:aws:s3:::example/*/test/*", "arn:aws:s3:::example//test/", true},
		{"missing slash", "arn:aws:s3:::example/*/test/*", "arn:aws:s3:::example/test/file", false},
		{"question single", "arn:aws:s3:::example/file?", "arn:aws:s3:::example/file1", true},
		{"question not empty", "arn:aws:s3:::example/file?", "arn:aws:s3:::example/file", false},
		{"question unicode", "arn:aws:s3:::example/file?", "arn:aws:s3:::example/fileé", true},
		{"brackets literal", "arn:aws:s3:::example/[a]", "arn:aws:s3:::example/a", false},
		{"literal bracket match", "arn:aws:s3:::example/[a]", "arn:aws:s3:::example/[a]", true},
		{"resource colon", "arn:aws:s3:::example/*suffix", "arn:aws:s3:::example/prefix:tail:suffix", true},
		{"incomplete arn", "arn:aws:sqs", "arn:aws:sqs:eu-west-1:123456789012:queue", true},
		{"different service", "arn:aws:sqs", "arn:aws:sns:eu-west-1:123456789012:topic", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc := mustParse(t, fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"*","Resource":%q}}`, tt.pattern))
			got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "s3:GetObject", Resource: tt.resource})
			if err != nil || (got == policy.Allow) != tt.allowed {
				t.Fatalf("Evaluate() = (%v, %v), want allowed %v", got, err, tt.allowed)
			}
		})
	}
}

func TestParseRejectsMalformedPolicies(t *testing.T) {
	for _, input := range []string{
		``, `null`, `[]`, `{}`, `{"Statement":null}`, `{"Statement":[]}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}} {}`,
		`{"Statement":{"Effect":"Deny","Effect":"Allow","Action":"*","Resource":"*"}}`,
		`{"Statement":{"Effect":"Deny","\u0045ffect":"Allow","Action":"*","Resource":"*"}}`,
		`{"statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		`{"Version":null,"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		`{"Version":"2024-01-01","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		`{"Id":"ResourcePolicyOnly","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		`{"Statement":{"Principal":"*","Effect":"Allow","Action":"*","Resource":"*"}}`,
		`{"Statement":{"NotPrincipal":"*","Effect":"Allow","Action":"*","Resource":"*"}}`,
		`{"Statement":{"Effect":"allow","Action":"*","Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","NotAction":"iam:*","Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","NotResource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Action":"*"}}`,
		`{"Statement":{"Effect":"Allow","Action":[],"Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Action":["s3:GetObject",42],"Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Action":"GetObject","Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Action":"s3:","Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"not-an-arn"}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"arn:aws:*:::bucket"}}`,
		`{"Statement":{"Sid":"contains-space bad","Effect":"Allow","Action":"*","Resource":"*"}}`,
		`{"Statement":[{"Sid":"Duplicate","Effect":"Allow","Action":"*","Resource":"*"},{"Sid":"Duplicate","Effect":"Deny","Action":"*","Resource":"*"}]}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{}}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"":"true"}}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":null}}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NullIfExists":{"key":"true"}}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"ForAllValues:Null":{"key":"true"}}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericEquals":{"key":"1/2"}}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericEquals":{"key":"NaN"}}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"DateEquals":{"key":"yesterday"}}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"IpAddress":{"key":"10.0.0.1/33"}}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"BinaryEquals":{"key":"bad base64"}}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"ArnEquals":{"key":"not-an-arn"}}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"key":"value","key":"other"}}}}`,
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := policy.Parse([]byte(input)); !errors.Is(err, policy.ErrInvalidPolicy) {
				t.Fatalf("Parse() error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestParseRejectsUnsupportedSemantics(t *testing.T) {
	for _, input := range []string{
		`{"Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"UnrecognizedOperator":{"key":"value"}}}}`,
	} {
		if _, err := policy.Parse([]byte(input)); !errors.Is(err, policy.ErrUnsupported) {
			t.Fatalf("Parse(%s) error = %v, want ErrUnsupported", input, err)
		}
	}
}

func TestParsePolicyVersions(t *testing.T) {
	for _, version := range []string{"", `"Version":"2008-10-17",`, `"Version":"2012-10-17",`} {
		mustParse(t, `{`+version+`"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	}
}

func TestEvaluateInvalidRequests(t *testing.T) {
	doc := mustParse(t, `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	for _, request := range []policy.Request{
		{},
		{Action: "s3:*", Resource: "*"},
		{Action: "s3:GetObject", Resource: ""},
		{Action: "s3:GetObject", Resource: "arn:aws:s3"},
		{Action: "s3:GetObject", Resource: "*", Context: map[string][]string{"Key": {"one"}, "key": {"two"}}},
		{Action: "s3:GetObject", Resource: "*", Context: map[string][]string{"": {"one"}}},
	} {
		got, err := policy.Evaluate([]*policy.Document{doc}, request)
		if got != policy.ImplicitDeny || !errors.Is(err, policy.ErrInvalidRequest) {
			t.Fatalf("Evaluate(%+v) = (%v, %v), want (implicitDeny, ErrInvalidRequest)", request, got, err)
		}
	}
	got, err := policy.Evaluate([]*policy.Document{nil}, policy.Request{Action: "s3:GetObject", Resource: "*"})
	if got != policy.ImplicitDeny || !errors.Is(err, policy.ErrInvalidPolicy) {
		t.Fatalf("Evaluate(nil document) = (%v, %v), want (implicitDeny, ErrInvalidPolicy)", got, err)
	}
}

func TestDocumentsSupportConcurrentEvaluation(t *testing.T) {
	data := []byte(`{"Statement":{"Effect":"Allow","Action":"s3:Get*","Resource":"arn:aws:s3:::example/*","Condition":{"NumericLessThanEquals":{"s3:max-keys":10}}}}`)
	doc, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	clear(data) // Document must not retain the caller's JSON buffer.
	var group sync.WaitGroup
	for range 20 {
		group.Go(func() {
			for range 20 {
				got, err := policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::example/file", Context: map[string][]string{"s3:max-keys": {"5"}}})
				if err != nil || got != policy.Allow {
					t.Errorf("Evaluate() = (%v, %v), want allowed", got, err)
				}
			}
		})
	}
	group.Wait()
}

func FuzzParseDoesNotPanic(f *testing.F) {
	for _, input := range []string{`{}`, `null`, `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NumericEquals":{"key":1e5}}}}`} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		// Policies are size-limited by the owning API. Bound fuzz-generated
		// inputs here to keep this parser check focused on syntax handling.
		if len(input) > 16_384 || strings.Count(input, "[")+strings.Count(input, "{") > 100 {
			t.Skip()
		}
		doc, err := policy.Parse([]byte(input))
		if err != nil {
			return
		}
		if !json.Valid([]byte(input)) || doc == nil {
			t.Fatal("Parse accepted invalid JSON or returned a nil document")
		}
		_, _ = policy.Evaluate([]*policy.Document{doc}, policy.Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::example/file"})
	})
}
