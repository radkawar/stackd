package stackd_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
)

func TestKMSImportedMaterialLossAndReimportPreserveQueueData(t *testing.T) {
	source := clock.NewManual(time.Now().UTC())
	c := clockCloud(t, stackd.Config{Clock: source})
	owner := c.kms("test", "test", "")
	k := kmsExternalKey(t, owner, types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, false)
	p := kmsImportParameters(t, owner, k.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
	in := kmsImportRequest(t, k.KeyId, p, bytes.Repeat([]byte{1}, 32), types.AlgorithmSpecRsaesOaepSha256)
	if _, err := owner.ImportKeyMaterial(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	queues := c.sqs("test", "test", "")
	queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("imported-key"), Attributes: map[string]string{"KmsMasterKeyId": aws.ToString(k.Arn), "KmsDataKeyReusePeriodSeconds": "60"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("before material deletion")}); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, time.Minute)
	_, err = queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("must not be queued")})
	assertAPIError(t, err, "KMS.InvalidStateException")
	_, err = queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
	assertAPIError(t, err, "KMS.InvalidStateException")
	if _, err := owner.ImportKeyMaterial(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	out, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
	if err != nil || len(out.Messages) != 1 || aws.ToString(out.Messages[0].Body) != "before material deletion" {
		t.Fatal("reimport failed to restore retained queue data", out, err)
	}
}
