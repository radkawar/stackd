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

	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
)

func clientForIAMPrincipal(t *testing.T, service *iam.Service, user *types.User) *sdkiam.Client {
	t.Helper()
	m := awsctx.FromContext(userContext(user, "aws"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		service.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), m)))
	}))
	t.Cleanup(server.Close)
	return sdkiam.New(sdkiam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), Retryer: aws.NopRetryer{}})
}

func TestIAMSDKEnforcesResourcePathsAndSelfPolicyChanges(t *testing.T) {
	service := iam.New()
	root := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("self"), Path: aws.String("/engineers/")})
	if err != nil {
		t.Fatal(err)
	}
	user := clientForIAMPrincipal(t, service, u.User)
	_, err = user.GetUser(ctx, &sdkiam.GetUserInput{})
	requireCode(t, err, "AccessDenied")
	_, err = user.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: u.User.UserName, PolicyName: aws.String("Escalate"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)})
	requireCode(t, err, "AccessDenied")
	grant := `{"Statement":{"Effect":"Allow","Action":["iam:GetUser","iam:PutUserPolicy"],"Resource":"` + aws.ToString(u.User.Arn) + `"}}`
	_, err = root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: u.User.UserName, PolicyName: aws.String("Self"), PolicyDocument: aws.String(grant)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := user.GetUser(ctx, &sdkiam.GetUserInput{})
	if err != nil || aws.ToString(got.User.Arn) != aws.ToString(u.User.Arn) {
		t.Fatalf("self path permission: %+v %v", got, err)
	}
	_, err = user.ListUsers(ctx, &sdkiam.ListUsersInput{})
	requireCode(t, err, "AccessDenied")
	readOnly := `{"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"` + aws.ToString(u.User.Arn) + `"}}`
	_, err = user.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: u.User.UserName, PolicyName: aws.String("Self"), PolicyDocument: aws.String(readOnly)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = user.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: u.User.UserName, PolicyName: aws.String("Self"), PolicyDocument: aws.String(grant)})
	requireCode(t, err, "AccessDenied")
	_, err = user.GetUser(ctx, &sdkiam.GetUserInput{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIAMSDKRequestTagConditions(t *testing.T) {
	service := iam.New()
	root := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("tagger")})
	if err != nil {
		t.Fatal(err)
	}
	document := `{"Statement":{"Effect":"Allow","Action":"iam:TagUser","Resource":"` + aws.ToString(u.User.Arn) + `","Condition":{"StringEquals":{"aws:RequestTag/team":"payments"},"ForAllValues:StringEquals":{"aws:TagKeys":["team"]}}}}`
	_, err = root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: u.User.UserName, PolicyName: aws.String("TagSelf"), PolicyDocument: aws.String(document)})
	if err != nil {
		t.Fatal(err)
	}
	user := clientForIAMPrincipal(t, service, u.User)
	_, err = user.TagUser(ctx, &sdkiam.TagUserInput{UserName: u.User.UserName, Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("admin")}}})
	requireCode(t, err, "AccessDenied")
	_, err = user.TagUser(ctx, &sdkiam.TagUserInput{UserName: u.User.UserName, Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("payments")}}})
	if err != nil {
		t.Fatal(err)
	}
	tags, err := root.ListUserTags(ctx, &sdkiam.ListUserTagsInput{UserName: u.User.UserName})
	if err != nil || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].Value) != "payments" {
		t.Fatalf("tag authorization mutation: %+v %v", tags, err)
	}
}
