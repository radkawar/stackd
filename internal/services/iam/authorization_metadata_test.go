package iam_test

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/services/iam"
)

// Unknown Query fields cannot become trusted authorization context. Send them
// directly because generated SDK inputs correctly have no such members.
func requireIAMMetadataQueryDenied(t *testing.T, service *iam.Service, user *types.User, query url.Values) {
	t.Helper()
	query.Set("Version", "2010-05-08")
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(query.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request.WithContext(userContext(user, "aws")))
	var envelope struct {
		Error struct {
			Code string `xml:"Code"`
		} `xml:"Error"`
	}
	if err := xml.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode denial: %v; response=%s", err, response.Body.String())
	}
	if response.Code != http.StatusForbidden || envelope.Error.Code != "AccessDenied" {
		t.Fatalf("injected %s request: status=%d code=%q body=%s", query.Get("Action"), response.Code, envelope.Error.Code, response.Body.String())
	}
}

func TestIAMAuthorizationMetadataBoundaryUsesCurrentResource(t *testing.T) {
	service := iam.New()
	root := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	actor, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("boundary-manager")})
	if err != nil {
		t.Fatal(err)
	}
	target, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("boundary-target"), Path: aws.String("/managed/")})
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := root.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{
		PolicyName: aws.String("RequiredBoundary"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := root.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{
		PolicyName: aws.String("AttachablePolicy"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*"}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	document := `{"Statement":{"Effect":"Allow","Action":["iam:AttachUserPolicy","iam:GetUser"],"Resource":"` + aws.ToString(target.User.Arn) + `","Condition":{"ArnEquals":{"iam:PermissionsBoundary":"` + aws.ToString(boundary.Policy.Arn) + `"}}}}`
	_, err = root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: actor.User.UserName, PolicyName: aws.String("RequireBoundary"), PolicyDocument: aws.String(document)})
	if err != nil {
		t.Fatal(err)
	}
	caller := clientForIAMPrincipal(t, service, actor.User)
	attach := &sdkiam.AttachUserPolicyInput{UserName: target.User.UserName, PolicyArn: payload.Policy.Arn}
	_, err = caller.AttachUserPolicy(ctx, attach)
	requireCode(t, err, "AccessDenied")
	requireIAMMetadataQueryDenied(t, service, actor.User, url.Values{
		"Action": {"AttachUserPolicy"}, "UserName": {aws.ToString(target.User.UserName)},
		"PolicyArn": {aws.ToString(payload.Policy.Arn)}, "PermissionsBoundary": {aws.ToString(boundary.Policy.Arn)},
	})
	attached, err := root.ListAttachedUserPolicies(ctx, &sdkiam.ListAttachedUserPoliciesInput{UserName: target.User.UserName})
	if err != nil || len(attached.AttachedPolicies) != 0 {
		t.Fatalf("denied injection changed attachments: %+v %v", attached, err)
	}
	_, err = root.PutUserPermissionsBoundary(ctx, &sdkiam.PutUserPermissionsBoundaryInput{UserName: target.User.UserName, PermissionsBoundary: boundary.Policy.Arn})
	if err != nil {
		t.Fatal(err)
	}
	_, err = caller.AttachUserPolicy(ctx, attach)
	if err != nil {
		t.Fatalf("actual matching resource boundary did not authorize attachment: %v", err)
	}
	// GetUser does not support iam:PermissionsBoundary, even when its resource
	// has the matching boundary. The same policy must not authorize this action.
	_, err = caller.GetUser(ctx, &sdkiam.GetUserInput{UserName: target.User.UserName})
	requireCode(t, err, "AccessDenied")
	_, err = root.DeleteUserPermissionsBoundary(ctx, &sdkiam.DeleteUserPermissionsBoundaryInput{UserName: target.User.UserName})
	if err != nil {
		t.Fatal(err)
	}
	_, err = caller.AttachUserPolicy(ctx, attach)
	requireCode(t, err, "AccessDenied")
}

func TestIAMAuthorizationMetadataIgnoresUnmodeledTagFields(t *testing.T) {
	service := iam.New()
	root := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	actor, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("tag-condition-caller")})
	if err != nil {
		t.Fatal(err)
	}
	target, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("tag-condition-target")})
	if err != nil {
		t.Fatal(err)
	}
	document := `{"Statement":[{"Effect":"Allow","Action":"iam:DeleteUser","Resource":"` + aws.ToString(target.User.Arn) + `","Condition":{"StringEquals":{"aws:RequestTag/team":"approved"}}},{"Effect":"Allow","Action":"iam:GetUser","Resource":"` + aws.ToString(target.User.Arn) + `","Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":"team"}}}]}`
	_, err = root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: actor.User.UserName, PolicyName: aws.String("UnsupportedRequestConditions"), PolicyDocument: aws.String(document)})
	if err != nil {
		t.Fatal(err)
	}
	caller := clientForIAMPrincipal(t, service, actor.User)
	_, err = caller.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: target.User.UserName})
	requireCode(t, err, "AccessDenied")
	_, err = caller.GetUser(ctx, &sdkiam.GetUserInput{UserName: target.User.UserName})
	requireCode(t, err, "AccessDenied")
	t.Run("delete-user-request-tags", func(t *testing.T) {
		requireIAMMetadataQueryDenied(t, service, actor.User, url.Values{
			"Action": {"DeleteUser"}, "UserName": {aws.ToString(target.User.UserName)},
			"Tags.member.1.Key": {"team"}, "Tags.member.1.Value": {"approved"},
		})
	})
	t.Run("get-user-tag-keys", func(t *testing.T) {
		requireIAMMetadataQueryDenied(t, service, actor.User, url.Values{
			"Action": {"GetUser"}, "UserName": {aws.ToString(target.User.UserName)}, "TagKeys.member.1": {"team"},
		})
	})
	got, err := root.GetUser(ctx, &sdkiam.GetUserInput{UserName: target.User.UserName})
	if err != nil || aws.ToString(got.User.UserId) != aws.ToString(target.User.UserId) {
		t.Fatalf("denied deletion changed the target user: %+v %v", got, err)
	}
}

func TestIAMAuthorizationMetadataPolicyResourceTagNamespace(t *testing.T) {
	service := iam.New()
	root := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	actor, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("policy-tag-reader")})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := root.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{
		PolicyName: aws.String("TaggedPolicy"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}}`),
		Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("approved")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	caller := clientForIAMPrincipal(t, service, actor.User)
	for _, namespace := range []string{"iam", "aws"} {
		t.Run(namespace, func(t *testing.T) {
			document := `{"Statement":{"Effect":"Allow","Action":"iam:GetPolicy","Resource":"` + aws.ToString(policy.Policy.Arn) + `","Condition":{"StringEquals":{"` + namespace + `:ResourceTag/team":"approved"}}}}`
			_, err := root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: actor.User.UserName, PolicyName: aws.String("PolicyTagRead"), PolicyDocument: aws.String(document)})
			if err != nil {
				t.Fatal(err)
			}
			got, err := caller.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: policy.Policy.Arn})
			if namespace == "iam" {
				requireCode(t, err, "AccessDenied")
				return
			}
			if err != nil || aws.ToString(got.Policy.PolicyId) != aws.ToString(policy.Policy.PolicyId) {
				t.Fatalf("supported aws:ResourceTag condition failed: %+v %v", got, err)
			}
		})
	}
	_, err = root.TagPolicy(ctx, &sdkiam.TagPolicyInput{PolicyArn: policy.Policy.Arn, Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("other")}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = caller.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: policy.Policy.Arn})
	requireCode(t, err, "AccessDenied")
}
