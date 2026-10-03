package stackd_test

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// Recreate the native operator as an IAM user so captured role trust and scoped
// actor policies retain their real principal, rather than using account root.
func gatewayNativeUser(t *testing.T, clients cloudClients, account, region, principalARN string) credentials.StaticCredentialsProvider {
	t.Helper()
	_, resource, ok := strings.Cut(principalARN, ":user/")
	if !ok || resource == "" {
		t.Fatalf("native gateway operator is not an IAM user: %s", principalARN)
	}
	cut := strings.LastIndexByte(resource, '/')
	name, path := resource[cut+1:], "/"+resource[:cut+1]
	operator := iam.NewFromConfig(aws.Config{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
	user, err := operator.CreateUser(t.Context(), &iam.CreateUserInput{UserName: &name, Path: &path})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(user.User.Arn) != principalARN {
		t.Fatalf("native operator prerequisite ARN=%s, native=%s", aws.ToString(user.User.Arn), principalARN)
	}
	policy := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	if _, err := operator.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: &name, PolicyName: aws.String("native-operator"), PolicyDocument: &policy}); err != nil {
		t.Fatal(err)
	}
	key, err := operator.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: &name})
	if err != nil {
		t.Fatal(err)
	}
	return credentials.NewStaticCredentialsProvider(*key.AccessKey.AccessKeyId, *key.AccessKey.SecretAccessKey, "")
}
