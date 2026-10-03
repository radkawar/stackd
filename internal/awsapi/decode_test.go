package awsapi_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	orgapi "stackd/internal/awsapi/organizations"
	stsapi "stackd/internal/awsapi/sts"
)

func TestGeneratedIAMQueryBinding(t *testing.T) {
	request, err := iamapi.DecodeRequest("CreateUser", awsapi.Request{Query: url.Values{"UserName": {"Alice"}, "Path": {"/engineering/"}, "Tags.member.1.Key": {"team"}, "Tags.member.1.Value": {"platform"}}})
	if err != nil {
		t.Fatal(err)
	}
	input, ok := request.Input.(*iamapi.CreateUserInput)
	if !ok {
		t.Fatalf("input type %T", request.Input)
	}
	if input.UserName == nil || string(*input.UserName) != "Alice" || input.Path == nil || string(*input.Path) != "/engineering/" || len(input.Tags) != 1 || string(*input.Tags[0].Key) != "team" || string(*input.Tags[0].Value) != "platform" {
		t.Fatalf("unexpected typed input: %+v", input)
	}
	ctx := awsapi.WithDecodedRequest(context.Background(), request)
	if got, ok := awsapi.Input[iamapi.CreateUserInput](ctx); !ok || got != input {
		t.Fatal("typed request was not preserved in context")
	}
	if _, ok := awsapi.Input[stsapi.AssumeRoleInput](ctx); ok {
		t.Fatal("wrong DTO type unexpectedly matched")
	}
}

func TestGeneratedOrganizationsJSONBinding(t *testing.T) {
	request, err := orgapi.DecodeRequest("CreateAccount", awsapi.Request{JSON: []byte(`{"Email":"owner@example.test","AccountName":"Development","Tags":[{"Key":"stage","Value":"dev"}],"UnknownFutureField":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	input, ok := request.Input.(*orgapi.CreateAccountInput)
	if !ok {
		t.Fatalf("input type %T", request.Input)
	}
	if input.Email == nil || string(*input.Email) != "owner@example.test" || input.AccountName == nil || string(*input.AccountName) != "Development" || len(input.Tags) != 1 {
		t.Fatalf("unexpected typed input: %+v", input)
	}
}

func TestGeneratedSTSQueryBinding(t *testing.T) {
	request, err := stsapi.DecodeRequest("AssumeRole", awsapi.Request{Query: url.Values{"RoleArn": {"arn:aws:iam::123456789012:role/demo"}, "RoleSessionName": {"local-session"}, "DurationSeconds": {"1800"}, "PolicyArns.member.1.arn": {"arn:aws:iam::123456789012:policy/demo"}, "Tags.member.1.Key": {"team"}, "Tags.member.1.Value": {"dev"}}})
	if err != nil {
		t.Fatal(err)
	}
	input, ok := request.Input.(*stsapi.AssumeRoleInput)
	if !ok {
		t.Fatalf("input type %T", request.Input)
	}
	if input.DurationSeconds == nil || int32(*input.DurationSeconds) != 1800 || len(input.PolicyArns) != 1 || len(input.Tags) != 1 {
		t.Fatalf("unexpected typed input: %+v", input)
	}
}

func TestGeneratedRequiredAndConstraints(t *testing.T) {
	for _, tt := range []struct {
		name, operation string
		query           url.Values
		path            string
	}{
		{"required", "CreateUser", url.Values{}, "UserName"},
		{"minimum length", "CreateUser", url.Values{"UserName": {""}}, "UserName"},
		{"maximum length", "CreateUser", url.Values{"UserName": {strings.Repeat("a", 65)}}, "UserName"},
		{"pattern", "CreateUser", url.Values{"UserName": {"bad user"}}, "UserName"},
		{"nested required", "CreateUser", url.Values{"UserName": {"Alice"}, "Tags.member.1.Value": {"dev"}}, "Tags[0].Key"},
		{"nested null collection", "CreateUser", url.Values{"UserName": {"Alice"}, "Tags.member.0.Key": {"key"}}, "Tags.member.0.Key"},
		{"numeric range", "ListUsers", url.Values{"MaxItems": {"0"}}, "MaxItems"},
		{"integer type", "ListUsers", url.Values{"MaxItems": {"1.5"}}, "MaxItems"},
		{"malformed number", "ListUsers", url.Values{"MaxItems": {"NaN"}}, "MaxItems"},
		{"malformed boolean", "ListPolicies", url.Values{"OnlyAttached": {"TRUE"}}, "OnlyAttached"},
		{"duplicate", "CreateUser", url.Values{"UserName": {"Alice", "Bob"}}, "UserName"},
		{"enum", "UpdateAccessKey", url.Values{"AccessKeyId": {"AKIA1234567890EXAMPLE"}, "Status": {"Unknown"}}, "Status"},
		{"negative lookahead", "CreateAccountAlias", url.Values{"AccountAlias": {"my--account"}}, "AccountAlias"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := iamapi.DecodeRequest(tt.operation, awsapi.Request{Query: tt.query})
			var validation *awsapi.ValidationError
			if !errors.As(err, &validation) || validation.Path != tt.path {
				t.Fatalf("error=%v, want ValidationError at %q", err, tt.path)
			}
		})
	}
}

func TestGeneratedJSONRejectsNullRequiredAndWrongTypes(t *testing.T) {
	for _, body := range []string{`{"Email":null,"AccountName":"Development"}`, `{"Email":42,"AccountName":"Development"}`, `{"Email":"owner@example.test","AccountName":"Development","Tags":[null]}`, `{"Email":"owner@example.test","AccountName":"Development","Tags":[{"Key":"stage"}]}`, `[]`, `not json`} {
		_, err := orgapi.DecodeRequest("CreateAccount", awsapi.Request{JSON: []byte(body)})
		var validation *awsapi.ValidationError
		if !errors.As(err, &validation) {
			t.Fatalf("body %s: error=%v, want ValidationError", body, err)
		}
	}
}

func TestUnknownOperationAndEmptyInput(t *testing.T) {
	if _, err := stsapi.DecodeRequest("NoSuchOperation", awsapi.Request{}); !errors.Is(err, awsapi.ErrUnknownOperation) {
		t.Fatalf("error=%v, want ErrUnknownOperation", err)
	}
	if _, err := stsapi.DecodeRequest("GetCallerIdentity", awsapi.Request{Query: url.Values{}}); err != nil {
		t.Fatal(err)
	}
}
