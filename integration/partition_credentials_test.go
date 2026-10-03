package stackd_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestIssuedCredentialsCannotCrossAWSPartitions(t *testing.T) {
	ctx := context.Background()
	c := newCloudClients(t)
	stsClient := func(region, key, secret, token string) *sts.Client {
		return sts.New(sts.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	}
	for _, region := range []string{"cn-north-1", "us-gov-west-1"} {
		t.Run(region, func(t *testing.T) {
			root := stsClient(region, "test", "test", "")
			session, err := root.GetSessionToken(ctx, &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
			if err != nil {
				t.Fatal(err)
			}
			token := session.Credentials
			if _, err := stsClient(region, aws.ToString(token.AccessKeyId), aws.ToString(token.SecretAccessKey), aws.ToString(token.SessionToken)).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
				t.Fatalf("session not valid in issuing partition: %v", err)
			}
			_, err = stsClient("us-east-1", aws.ToString(token.AccessKeyId), aws.ToString(token.SecretAccessKey), aws.ToString(token.SessionToken)).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			assertAPIError(t, err, "InvalidClientTokenId")
			iamClient := iam.New(iam.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			if _, err := iamClient.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("partition-user")}); err != nil {
				t.Fatal(err)
			}
			key, err := iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String("partition-user")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = stsClient("us-east-1", aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey), "").GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			assertAPIError(t, err, "InvalidClientTokenId")
		})
	}
}
