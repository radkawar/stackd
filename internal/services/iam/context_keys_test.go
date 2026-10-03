package iam_test

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	policyeval "stackd/iam/policy"
	"stackd/internal/services/iam"
)

func TestContextKeysReplayAWS(t *testing.T) {
	data, err := os.ReadFile("testdata/context_keys_aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Custom []struct {
			Name      string                             `json:"name"`
			Documents []json.RawMessage                  `json:"documents"`
			ErrorCode string                             `json:"error_code"`
			Response  struct{ ContextKeyNames []string } `json:"response"`
		} `json:"custom"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	client := clientFor(t, iam.New(), "123456789012", "us-east-1")
	for _, tc := range fixture.Custom {
		t.Run(tc.Name, func(t *testing.T) {
			documents := make([]string, 0, len(tc.Documents))
			for _, document := range tc.Documents {
				documents = append(documents, string(document))
			}
			got, err := client.GetContextKeysForCustomPolicy(context.Background(), &sdkiam.GetContextKeysForCustomPolicyInput{PolicyInputList: documents})
			if tc.ErrorCode != "" {
				requireCode(t, err, tc.ErrorCode)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			slices.Sort(got.ContextKeyNames)
			slices.Sort(tc.Response.ContextKeyNames)
			if !slices.Equal(got.ContextKeyNames, tc.Response.ContextKeyNames) {
				t.Fatalf("keys=%v, AWS=%v", got.ContextKeyNames, tc.Response.ContextKeyNames)
			}
		})
	}
}

func TestPrincipalContextKeysCurrentPoliciesAndAuthorization(t *testing.T) {
	s := iam.New()
	client := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	doc := func(key string) string {
		return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"` + key + `":"x"}}}}`
	}
	u, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("context-user"), Path: aws.String("/context/")})
	if err != nil {
		t.Fatal(err)
	}
	g, err := client.CreateGroup(ctx, &sdkiam.CreateGroupInput{GroupName: aws.String("context-group")})
	if err != nil {
		t.Fatal(err)
	}
	p, err := client.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("ContextManaged"), PolicyDocument: aws.String(doc("aws:PrincipalTag/Managed"))})
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("ContextBoundary"), PolicyDocument: aws.String(doc("aws:PrincipalTag/BoundaryOnly"))})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: u.User.UserName, PolicyName: aws.String("inline"), PolicyDocument: aws.String(doc("aws:PrincipalTag/UserInline"))})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.PutGroupPolicy(ctx, &sdkiam.PutGroupPolicyInput{GroupName: g.Group.GroupName, PolicyName: aws.String("inline"), PolicyDocument: aws.String(doc("aws:PrincipalTag/GroupInline"))})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AttachUserPolicy(ctx, &sdkiam.AttachUserPolicyInput{UserName: u.User.UserName, PolicyArn: p.Policy.Arn})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AttachGroupPolicy(ctx, &sdkiam.AttachGroupPolicyInput{GroupName: g.Group.GroupName, PolicyArn: p.Policy.Arn})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AddUserToGroup(ctx, &sdkiam.AddUserToGroupInput{UserName: u.User.UserName, GroupName: g.Group.GroupName})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.PutUserPermissionsBoundary(ctx, &sdkiam.PutUserPermissionsBoundaryInput{UserName: u.User.UserName, PermissionsBoundary: b.Policy.Arn})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"aws:PrincipalTag/BoundaryOnly", "aws:PrincipalTag/GroupInline", "aws:PrincipalTag/Managed", "aws:PrincipalTag/UserInline"}
	check := func(client *sdkiam.Client, arn string, extra []string, want []string) {
		t.Helper()
		got, err := client.GetContextKeysForPrincipalPolicy(ctx, &sdkiam.GetContextKeysForPrincipalPolicyInput{PolicySourceArn: aws.String(arn), PolicyInputList: extra})
		if err != nil {
			t.Fatal(err)
		}
		slices.Sort(got.ContextKeyNames)
		want = slices.Clone(want)
		slices.Sort(want)
		if !slices.Equal(got.ContextKeyNames, want) {
			t.Fatalf("keys=%v want=%v", got.ContextKeyNames, want)
		}
	}
	check(client, aws.ToString(u.User.Arn), nil, want)
	check(client, strings.Replace(aws.ToString(u.User.Arn), "/context/", "/missing/", 1), nil, want)
	check(client, aws.ToString(u.User.Arn), []string{doc("aws:PrincipalTag/UserInline")}, append(slices.Clone(want), "aws:PrincipalTag/UserInline"))
	check(client, aws.ToString(g.Group.Arn), nil, []string{"aws:PrincipalTag/GroupInline", "aws:PrincipalTag/Managed"})
	_, err = client.CreatePolicyVersion(ctx, &sdkiam.CreatePolicyVersionInput{PolicyArn: p.Policy.Arn, PolicyDocument: aws.String(doc("aws:PrincipalTag/Changed")), SetAsDefault: true})
	if err != nil {
		t.Fatal(err)
	}
	want[2] = "aws:PrincipalTag/Changed"
	check(client, aws.ToString(u.User.Arn), nil, want)
	actor, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("context-reader")})
	if err != nil {
		t.Fatal(err)
	}
	caller := clientForIAMPrincipal(t, s, actor.User)
	_, err = caller.GetContextKeysForPrincipalPolicy(ctx, &sdkiam.GetContextKeysForPrincipalPolicyInput{PolicySourceArn: u.User.Arn})
	requireCode(t, err, "AccessDenied")
	permission := `{"Statement":{"Effect":"Allow","Action":"iam:GetContextKeysForPrincipalPolicy","Resource":"` + aws.ToString(u.User.Arn) + `"}}`
	_, err = client.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: actor.User.UserName, PolicyName: aws.String("read"), PolicyDocument: aws.String(permission)})
	if err != nil {
		t.Fatal(err)
	}
	check(caller, aws.ToString(u.User.Arn), nil, want)
	_, err = caller.GetContextKeysForPrincipalPolicy(ctx, &sdkiam.GetContextKeysForPrincipalPolicyInput{PolicySourceArn: g.Group.Arn})
	requireCode(t, err, "AccessDenied")
	_, err = client.GetContextKeysForPrincipalPolicy(ctx, &sdkiam.GetContextKeysForPrincipalPolicyInput{PolicySourceArn: aws.String("arn:aws:iam::123456789012:user/missing")})
	requireCode(t, err, "NoSuchEntity")
	_, err = client.GetContextKeysForPrincipalPolicy(ctx, &sdkiam.GetContextKeysForPrincipalPolicyInput{PolicySourceArn: aws.String("arn:aws-cn:iam::123456789012:user/context-user")})
	requireCode(t, err, "AccessDenied")
	for _, arn := range []string{"this-is-not-an-iam-source-arn", "arn:aws:iam::123456789012:root", "arn:aws:iam:us-east-1:123456789012:user/context-user"} {
		_, err = client.GetContextKeysForPrincipalPolicy(ctx, &sdkiam.GetContextKeysForPrincipalPolicyInput{PolicySourceArn: aws.String(arn)})
		requireCode(t, err, "InvalidInput")
	}
}

func TestContextIntrospectionDoesNotRelaxEnforcementGrammar(t *testing.T) {
	document := []byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericEquals":{"aws:MultiFactorAuthAge":"not-a-number"}}}}`)
	if _, err := policyeval.ContextKeys(document); err != nil {
		t.Fatal(err)
	}
	if _, err := policyeval.Parse(document); err == nil {
		t.Fatal("introspection grammar accepted for authorization")
	}
}
