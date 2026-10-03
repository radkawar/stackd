package sqs

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"stackd/internal/awswire"
)

func TestQueueResourcePermissionsApplyToCrossAccountDelivery(t *testing.T) {
	_, owner, _, server := fixture(t)
	ctx := context.Background()
	url := create(t, owner, "shared", nil)
	other := testClient(server, "222222222222", "us-east-1")
	_, err := other.SendMessage(ctx, &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String("denied")})
	requireCode(t, err, "AccessDenied")
	_, err = owner.AddPermission(ctx, &sdk.AddPermissionInput{QueueUrl: aws.String(url), Label: aws.String("ExternalSender"), AWSAccountIds: []string{"222222222222"}, Actions: []string{"SendMessage", "GetQueueUrl"}})
	if err != nil {
		t.Fatal(err)
	}
	looked, err := other.GetQueueUrl(ctx, &sdk.GetQueueUrlInput{QueueName: aws.String("shared"), QueueOwnerAWSAccountId: aws.String("111111111111")})
	if err != nil || aws.ToString(looked.QueueUrl) != url {
		t.Fatalf("cross-account queue URL=%v %v", looked, err)
	}
	send(t, other, url, "allowed")
	_, err = other.ReceiveMessage(ctx, &sdk.ReceiveMessageInput{QueueUrl: aws.String(url)})
	requireCode(t, err, "AccessDenied")
	messages := receive(t, owner, url, 1)
	if len(messages) != 1 || messages[0].Attributes["SenderId"] != "222222222222" {
		t.Fatalf("cross-account message=%v", messages)
	}
	_, err = owner.RemovePermission(ctx, &sdk.RemovePermissionInput{QueueUrl: aws.String(url), Label: aws.String("ExternalSender")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = other.SendMessage(ctx, &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String("denied-again")})
	requireCode(t, err, "AccessDenied")
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"sqs:SendMessage","Resource":"` + attributes(t, owner, url)["QueueArn"] + `"}]}`
	_, err = owner.SetQueueAttributes(ctx, &sdk.SetQueueAttributesInput{QueueUrl: aws.String(url), Attributes: map[string]string{"Policy": policy}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = owner.SendMessage(ctx, &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String("root-denied")})
	requireCode(t, err, "AccessDenied")
}

type testKMS struct {
	mu                            sync.Mutex
	generated, decrypted, ensured int
	disabled                      bool
	contexts                      []map[string]string
	values                        map[string][]byte
}

func (k *testKMS) GenerateDataKey(_ context.Context, id string, ec map[string]string) ([]byte, []byte, string, *awswire.Error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.generated++
	k.contexts = append(k.contexts, ec)
	if k.disabled {
		return nil, nil, "", &awswire.Error{Code: "DisabledException", Message: "disabled", StatusCode: 400}
	}
	plaintext := make([]byte, 32)
	plaintext[0] = byte(k.generated)
	ciphertext := []byte("encrypted:" + id + ":" + identifier())
	if k.values == nil {
		k.values = make(map[string][]byte)
	}
	k.values[string(ciphertext)] = append([]byte(nil), plaintext...)
	return plaintext, ciphertext, "arn:aws:kms:us-east-1:111111111111:key/test", nil
}
func (k *testKMS) Decrypt(_ context.Context, ciphertext []byte, ec map[string]string) ([]byte, string, *awswire.Error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.decrypted++
	k.contexts = append(k.contexts, ec)
	if k.disabled {
		return nil, "", &awswire.Error{Code: "DisabledException", Message: "disabled", StatusCode: 400}
	}
	return append([]byte(nil), k.values[string(ciphertext)]...), "arn:aws:kms:us-east-1:111111111111:key/test", nil
}
func (k *testKMS) EnsureServiceKey(context.Context, string) (string, *awswire.Error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ensured++
	return "arn:aws:kms:us-east-1:111111111111:key/test", nil
}
func TestKMSEnvelopeKeysReuseAndExistingMessagesAfterReconfiguration(t *testing.T) {
	backend := &testKMS{}
	clock := newClock()
	s := NewWithConfig(Config{KMS: backend, Clock: clock})
	server := testServer(t, s)
	c := testClient(server, "111111111111", "us-east-1")
	ctx := context.Background()
	url := create(t, c, "encrypted", map[string]string{"KmsMasterKeyId": "alias/aws/sqs", "KmsDataKeyReusePeriodSeconds": "60"})
	send(t, c, url, "one")
	send(t, c, url, "two")
	backend.mu.Lock()
	if backend.generated != 1 || backend.decrypted != 1 || backend.ensured != 1 {
		t.Errorf("unexpected key calls generated=%d decrypted=%d ensured=%d", backend.generated, backend.decrypted, backend.ensured)
	}
	for _, ec := range backend.contexts {
		if ec["aws:sqs:arn"] != "arn:aws:sqs:us-east-1:111111111111:encrypted" {
			t.Errorf("encryption context=%v", ec)
		}
	}
	backend.mu.Unlock()
	s.mu.Lock()
	for _, q := range s.queues {
		for _, m := range q.messages {
			if m.keyARN == "" || len(m.dataKey) == 0 || json.Valid(m.data) {
				t.Error("KMS message not encrypted")
			}
		}
	}
	s.mu.Unlock()
	advance(t, clock, time.Minute)
	backend.mu.Lock()
	backend.disabled = true
	backend.mu.Unlock()
	_, err := c.SendMessage(ctx, &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String("cannot encrypt")})
	requireCode(t, err, "KMS.DisabledException")
	_, err = c.ReceiveMessage(ctx, &sdk.ReceiveMessageInput{QueueUrl: aws.String(url)})
	requireCode(t, err, "KMS.DisabledException")
	if attributes(t, c, url)["ApproximateNumberOfMessages"] != "2" {
		t.Fatal("KMS failure changed queue state")
	}
	_, err = c.SetQueueAttributes(ctx, &sdk.SetQueueAttributesInput{QueueUrl: aws.String(url), Attributes: map[string]string{"KmsMasterKeyId": "", "SqsManagedSseEnabled": "false"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ReceiveMessage(ctx, &sdk.ReceiveMessageInput{QueueUrl: aws.String(url)})
	requireCode(t, err, "KMS.DisabledException")
	backend.mu.Lock()
	backend.disabled = false
	backend.mu.Unlock()
	if len(receive(t, c, url, 10)) != 2 {
		t.Fatal("existing encrypted messages failed after queue reconfiguration")
	}
}
