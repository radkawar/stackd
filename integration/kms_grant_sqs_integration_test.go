package stackd_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
)

func TestKMSSessionGrantAllowsEncryptedQueueDelivery(t *testing.T) {
	source := clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	c := clockCloud(t, stackd.Config{Clock: source})
	owner, root := c.kms("test", "test", ""), c.iam("test", "test", "")
	key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	queueARN := "arn:aws:sqs:us-east-1:000000000000:grant-queue"
	queue, err := c.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("grant-queue"), Attributes: map[string]string{"KmsMasterKeyId": aws.ToString(key.KeyMetadata.Arn), "KmsDataKeyReusePeriodSeconds": "60"}})
	if err != nil {
		t.Fatal(err)
	}
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("queue-worker"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	document := allow(`"sqs:*"`, queueARN)
	putRolePolicy(t, root, "queue-worker", document)
	session, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("delivery"), Policy: &document})
	if err != nil {
		t.Fatal(err)
	}
	client := c.sessionSQS(session.Credentials)
	message := &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("session-encrypted message")}
	_, err = client.SendMessage(t.Context(), message)
	assertAPIError(t, err, "KMS.AccessDeniedException")
	grant, err := owner.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyMetadata.KeyId, GranteePrincipal: session.AssumedRoleUser.Arn, Operations: []types.GrantOperation{types.GrantOperationGenerateDataKey, types.GrantOperationDecrypt}, Constraints: &types.GrantConstraints{EncryptionContextEquals: map[string]string{"aws:sqs:arn": queueARN}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SendMessage(t.Context(), message); err != nil {
		t.Fatal("SQS did not consume exact-session KMS grant", err)
	}
	got, err := client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
	if err != nil || len(got.Messages) != 1 || aws.ToString(got.Messages[0].Body) != aws.ToString(message.MessageBody) {
		t.Fatal("SQS grant decryption failed", got, err)
	}
	// Service forwarding preserves the caller identity and the grant's context.
	_, err = c.sessionKMS(session.Credentials).GenerateDataKey(t.Context(), &kms.GenerateDataKeyInput{KeyId: key.KeyMetadata.KeyId, KeySpec: types.DataKeySpecAes256, EncryptionContext: map[string]string{"aws:sqs:arn": queueARN + "-other"}})
	assertAPIError(t, err, "AccessDeniedException")
	if _, err := owner.RevokeGrant(t.Context(), &kms.RevokeGrantInput{KeyId: key.KeyMetadata.KeyId, GrantId: grant.GrantId}); err != nil {
		t.Fatal(err)
	}
	// SQS legitimately reuses its data key. At the configured reuse deadline,
	// both sending and receiving must reauthorize KMS and observe revocation.
	advanceClock(t, source, time.Minute)
	_, err = client.SendMessage(t.Context(), message)
	assertAPIError(t, err, "KMS.AccessDeniedException")
	_, err = client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
	assertAPIError(t, err, "KMS.AccessDeniedException")
}
