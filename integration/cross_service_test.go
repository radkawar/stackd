package stackd_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

func TestQueueKMSChecksCallerPermissionsBeforeDelivery(t *testing.T) {
	ctx := context.Background()
	c := newCloudClients(t)
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "producer")
	kmsClient := kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	encryptionKey, err := kmsClient.CreateKey(ctx, &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := c.sqs("test", "test", "").CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("encrypted"), Attributes: map[string]string{"KmsMasterKeyId": aws.ToString(encryptionKey.KeyMetadata.Arn)}})
	if err != nil {
		t.Fatal(err)
	}
	putUserPolicy(t, root, "producer", allow(`"sqs:SendMessage"`, "*"))
	sender := c.sqs(key, secret, "")
	_, err = sender.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("denied")})
	assertAPIError(t, err, "KMS.AccessDeniedException")
	putUserPolicy(t, root, "producer", allow(`["sqs:SendMessage","kms:GenerateDataKey","kms:Decrypt"]`, "*"))
	if _, err := sender.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("encrypted payload")}); err != nil {
		t.Fatal(err)
	}
	receiver := c.sqs("test", "test", "")
	messages, err := receiver.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
	if err != nil || len(messages.Messages) != 1 || aws.ToString(messages.Messages[0].Body) != "encrypted payload" {
		t.Fatalf("KMS/SQS delivery: %#v %v", messages, err)
	}
}

func TestOrganizationsSCPRestrictsMemberRootAndIAMUser(t *testing.T) {
	ctx := context.Background()
	c := newCloudClients(t)
	org := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	if _, err := org.CreateOrganization(ctx, &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll}); err != nil {
		t.Fatal(err)
	}
	account, err := org.CreateAccount(ctx, &organizations.CreateAccountInput{AccountName: aws.String("application"), Email: aws.String("application@example.test")})
	if err != nil {
		t.Fatal(err)
	}
	account.CreateAccountStatus = waitAccountCreation(t, org, account.CreateAccountStatus, nil)
	accountID := aws.ToString(account.CreateAccountStatus.AccountId)
	if accountID == "" {
		t.Fatal("account creation did not complete")
	}
	member := c.sqs(accountID, "test", "")
	queue, err := member.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("guarded")})
	if err != nil {
		t.Fatal(err)
	}
	_, key, secret := c.user(t, accountID, "application")
	putUserPolicy(t, c.iam(accountID, "test", ""), "application", allow(`"sqs:SendMessage"`, "*"))
	user := c.sqs(key, secret, "")
	if _, err := user.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("before guardrail")}); err != nil {
		t.Fatal(err)
	}
	policy, err := org.CreatePolicy(ctx, &organizations.CreatePolicyInput{Name: aws.String("deny-send"), Description: aws.String("guardrail"), Type: orgtypes.PolicyTypeServiceControlPolicy, Content: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":["sqs:SendMessage","iam:CreateUser"],"Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := org.AttachPolicy(ctx, &organizations.AttachPolicyInput{PolicyId: policy.Policy.PolicySummary.Id, TargetId: aws.String(accountID)}); err != nil {
		t.Fatal(err)
	}
	for _, caller := range []*sqs.Client{member, user} {
		_, err := caller.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("blocked")})
		assertAPIError(t, err, "AccessDenied")
	}
	_, err = c.iam(accountID, "test", "").CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("blocked")})
	assertAPIError(t, err, "AccessDenied")
	if _, err := org.DetachPolicy(ctx, &organizations.DetachPolicyInput{PolicyId: policy.Policy.PolicySummary.Id, TargetId: aws.String(accountID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := member.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("after guardrail removed")}); err != nil {
		t.Fatal(err)
	}
	messages, err := member.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
	if err != nil || len(messages.Messages) != 2 {
		t.Fatalf("denied requests changed state: %#v %v", messages, err)
	}
}
