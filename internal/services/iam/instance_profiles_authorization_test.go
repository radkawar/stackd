package iam_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/services/iam"
)

func TestInstanceProfileAuthorizationAndPassRole(t *testing.T) {
	s := iam.New()
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	user, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("Provisioner")})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.ServeHTTP(w, r.WithContext(userContext(user.User, "aws")))
	}))
	t.Cleanup(server.Close)
	client := sdkiam.New(sdkiam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("unused", "unused", ""), Retryer: aws.NopRetryer{}})
	put := func(name, document string) {
		t.Helper()
		if _, err := root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String(name), PolicyDocument: aws.String(document)}); err != nil {
			t.Fatal(err)
		}
	}
	profileARN := "arn:aws:iam::123456789012:instance-profile/apps/Web"
	put("Provision", `{"Statement":{"Effect":"Allow","Action":["iam:CreateInstanceProfile","iam:AddRoleToInstanceProfile","iam:RemoveRoleFromInstanceProfile"],"Resource":"`+profileARN+`"}}`)
	create := &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String("Web"), Path: aws.String("/apps/"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("compute")}}}
	_, err = client.CreateInstanceProfile(ctx, create)
	requireCode(t, err, "AccessDenied")
	_, err = root.GetInstanceProfile(ctx, &sdkiam.GetInstanceProfileInput{InstanceProfileName: aws.String("Web")})
	requireCode(t, err, "NoSuchEntity")
	put("Tag", `{"Statement":{"Effect":"Allow","Action":"iam:TagInstanceProfile","Resource":"`+profileARN+`","Condition":{"StringEquals":{"aws:RequestTag/team":"compute"},"ForAllValues:StringEquals":{"aws:TagKeys":["team"]}}}}`)
	if _, err := client.CreateInstanceProfile(ctx, create); err != nil {
		t.Fatalf("tag-authorized creation: %v", err)
	}
	role, err := root.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("Compute"), Path: aws.String("/roles/"), AssumeRolePolicyDocument: aws.String(trustEC2)})
	if err != nil {
		t.Fatal(err)
	}
	add := &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String("Web"), RoleName: role.Role.RoleName}
	_, err = client.AddRoleToInstanceProfile(ctx, add)
	requireCode(t, err, "AccessDenied")
	for _, tc := range []struct{ name, condition string }{
		{"wrong-service", `"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}`},
		{"concrete-region", `"ArnLike":{"iam:AssociatedResourceArn":"arn:aws:ec2:us-east-1:123456789012:instance/*"}`},
	} {
		put("Pass", `{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"`+aws.ToString(role.Role.Arn)+`","Condition":{`+tc.condition+`}}}`)
		_, err = client.AddRoleToInstanceProfile(ctx, add)
		requireCode(t, err, "AccessDenied")
	}
	got, err := root.GetInstanceProfile(ctx, &sdkiam.GetInstanceProfileInput{InstanceProfileName: aws.String("Web")})
	if err != nil || len(got.InstanceProfile.Roles) != 0 {
		t.Fatalf("denied PassRole mutated membership: %+v, %v", got, err)
	}
	put("Pass", `{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"`+aws.ToString(role.Role.Arn)+`","Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"},"ArnLike":{"iam:AssociatedResourceArn":"arn:aws:ec2:*:123456789012:instance/*"}}}}`)
	if _, err := client.AddRoleToInstanceProfile(ctx, add); err != nil {
		t.Fatalf("scoped PassRole denied: %v", err)
	}
	put("Read", `{"Statement":[{"Effect":"Allow","Action":"iam:GetInstanceProfile","Resource":"`+profileARN+`","Condition":{"StringEquals":{"aws:ResourceTag/team":"compute"}}},{"Effect":"Allow","Action":"iam:ListInstanceProfilesForRole","Resource":"`+aws.ToString(role.Role.Arn)+`"}]}`)
	if _, err := client.GetInstanceProfile(ctx, &sdkiam.GetInstanceProfileInput{InstanceProfileName: aws.String("WEB")}); err != nil {
		t.Fatalf("current path/tag authorization: %v", err)
	}
	list, err := client.ListInstanceProfilesForRole(ctx, &sdkiam.ListInstanceProfilesForRoleInput{RoleName: aws.String("compute")})
	if err != nil || len(list.InstanceProfiles) != 1 {
		t.Fatalf("role resource authorization = %+v, %v", list, err)
	}
	_, err = client.ListInstanceProfiles(ctx, &sdkiam.ListInstanceProfilesInput{})
	requireCode(t, err, "AccessDenied")
	put("Pass", `{"Statement":{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}}`)
	if _, err := client.RemoveRoleFromInstanceProfile(ctx, &sdkiam.RemoveRoleFromInstanceProfileInput{InstanceProfileName: aws.String("Web"), RoleName: role.Role.RoleName}); err != nil {
		t.Fatalf("removal incorrectly required PassRole: %v", err)
	}
}
