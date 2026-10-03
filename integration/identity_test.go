package stackd_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"stackd"
)

func TestSDKIAMCredentialsAndSTSSession(t *testing.T) {
	ctx := context.Background()
	handler, err := stackd.New(stackd.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	iamClient := func(key, secret, token string) *iam.Client {
		return iam.New(iam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	}
	stsClient := func(key, secret, token string) *sts.Client {
		return sts.New(sts.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	}
	root := iamClient("test", "test", "")
	user, err := root.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("alice"), Path: aws.String("/engineering/")})
	if err != nil {
		t.Fatal(err)
	}
	key, err := root.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String("alice")})
	if err != nil {
		t.Fatal(err)
	}
	accessKey, secret := aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey)
	identity, err := stsClient(accessKey, secret, "").GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(identity.Arn) != aws.ToString(user.User.Arn) || aws.ToString(identity.UserId) != aws.ToString(user.User.UserId) {
		t.Fatalf("wrong principal: %#v", identity)
	}
	_, err = root.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: aws.String("alice"), PolicyName: aws.String("read-self"), PolicyDocument: aws.String(allow(`"iam:GetUser"`, aws.ToString(user.User.Arn)))})
	if err != nil {
		t.Fatal(err)
	}
	self, err := iamClient(accessKey, secret, "").GetUser(ctx, &iam.GetUserInput{})
	if err != nil || aws.ToString(self.User.UserName) != "alice" {
		t.Fatalf("GetUser: %#v %v", self, err)
	}
	session, err := stsClient(accessKey, secret, "").GetSessionToken(ctx, &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
	if err != nil {
		t.Fatal(err)
	}
	temporary := session.Credentials
	temporaryClient := stsClient(aws.ToString(temporary.AccessKeyId), aws.ToString(temporary.SecretAccessKey), aws.ToString(temporary.SessionToken))
	identity, err = temporaryClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(identity.Arn) != aws.ToString(user.User.Arn) {
		t.Fatalf("session identity: %#v %v", identity, err)
	}
	for _, token := range []string{"", "forged"} {
		_, err := stsClient(aws.ToString(temporary.AccessKeyId), aws.ToString(temporary.SecretAccessKey), token).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		assertAPIError(t, err, "InvalidClientTokenId")
	}
	_, err = iamClient(aws.ToString(temporary.AccessKeyId), aws.ToString(temporary.SecretAccessKey), aws.ToString(temporary.SessionToken)).GetUser(ctx, &iam.GetUserInput{})
	assertAPIError(t, err, "AccessDenied")
	usage, err := root.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: aws.String(accessKey)})
	if err != nil {
		t.Fatal(err)
	}
	if usage.AccessKeyLastUsed.LastUsedDate == nil || aws.ToString(usage.AccessKeyLastUsed.ServiceName) != "sts" {
		t.Fatalf("missing usage: %#v", usage.AccessKeyLastUsed)
	}
	_, err = root.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{UserName: aws.String("alice"), AccessKeyId: aws.String(accessKey), Status: iamtypes.StatusTypeInactive})
	if err != nil {
		t.Fatal(err)
	}
	_, err = stsClient(accessKey, secret, "").GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	assertAPIError(t, err, "InvalidClientTokenId")
	_, err = root.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: aws.String("alice"), AccessKeyId: aws.String(accessKey)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = stsClient(accessKey, secret, "").GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	assertAPIError(t, err, "InvalidClientTokenId")
}

func assertAPIError(t *testing.T, err error, code string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != code {
		t.Fatalf("got %v; want %s", err, code)
	}
}
