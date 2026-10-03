package stackd_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
)

func TestKMSRotationPolicyDefaultsAndCrossAccountStatus(t *testing.T) {
	c := clockCloud(t, stackd.Config{})
	owner := c.kms("test", "test", "")
	policy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"kms:*","Resource":"*"}]}`
	created, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	k := created.KeyMetadata
	_, access, secret := c.user(t, "test", "rotation-operator")
	operator := c.kms(access, secret, "")
	document := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"kms:EnableKeyRotation","Resource":%q,"Condition":{"NumericLessThanEquals":{"kms:RotationPeriodInDays":"100"}}},{"Effect":"Allow","Action":"kms:GetKeyRotationStatus","Resource":%q}]}`, aws.ToString(k.Arn), aws.ToString(k.Arn))
	putUserPolicy(t, c.iam("test", "test", ""), "rotation-operator", document)
	if _, err := operator.EnableKeyRotation(t.Context(), &kms.EnableKeyRotationInput{KeyId: k.KeyId, RotationPeriodInDays: aws.Int32(90)}); err != nil {
		t.Fatal(err)
	}
	// Native evidence confirms an omitted parameter authorizes as 365, even
	// when this key is already configured for a 90-day rotation period.
	for _, period := range []*int32{nil, aws.Int32(180)} {
		_, err := operator.EnableKeyRotation(t.Context(), &kms.EnableKeyRotationInput{KeyId: k.KeyId, RotationPeriodInDays: period})
		assertAPIError(t, err, "AccessDeniedException")
	}
	status, err := operator.GetKeyRotationStatus(t.Context(), &kms.GetKeyRotationStatusInput{KeyId: k.KeyId})
	if err != nil || aws.ToInt32(status.RotationPeriodInDays) != 90 {
		t.Fatal("denied requests changed the schedule", err)
	}
	_, err = operator.DisableKeyRotation(t.Context(), &kms.DisableKeyRotationInput{KeyId: k.KeyId})
	assertAPIError(t, err, "AccessDeniedException")
	_, extAccess, extSecret := c.user(t, "222222222222", "rotation-reader")
	external := c.kms(extAccess, extSecret, "")
	_, err = external.GetKeyRotationStatus(t.Context(), &kms.GetKeyRotationStatusInput{KeyId: k.Arn})
	assertAPIError(t, err, "AccessDeniedException")
	putUserPolicy(t, c.iam("222222222222", "test", ""), "rotation-reader", allow(`"kms:*"`, aws.ToString(k.Arn)))
	if out, err := external.GetKeyRotationStatus(t.Context(), &kms.GetKeyRotationStatusInput{KeyId: k.Arn}); err != nil || !out.KeyRotationEnabled {
		t.Fatal("cross-account rotation status", err)
	}
	_, err = external.EnableKeyRotation(t.Context(), &kms.EnableKeyRotationInput{KeyId: k.Arn})
	assertAPIError(t, err, "AccessDeniedException")
	_, err = external.DisableKeyRotation(t.Context(), &kms.DisableKeyRotationInput{KeyId: k.Arn})
	assertAPIError(t, err, "AccessDeniedException")
	_, err = external.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: k.Arn})
	assertAPIError(t, err, "AccessDeniedException")
	_, err = external.ListKeyRotations(t.Context(), &kms.ListKeyRotationsInput{KeyId: k.Arn})
	assertAPIError(t, err, "AccessDeniedException")
}

func TestKMSAutomaticRotationPreservesEncryptedQueueDelivery(t *testing.T) {
	source := clock.NewManual(time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC))
	c := clockCloud(t, stackd.Config{Clock: source})
	owner := c.kms("test", "test", "")
	created, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	k := created.KeyMetadata
	if _, err := owner.EnableKeyRotation(t.Context(), &kms.EnableKeyRotationInput{KeyId: k.KeyId, RotationPeriodInDays: aws.Int32(90)}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 90*24*time.Hour-time.Minute)
	queues := c.sqs("test", "test", "")
	queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("rotating-encryption"), Attributes: map[string]string{"KmsMasterKeyId": aws.ToString(k.Arn), "KmsDataKeyReusePeriodSeconds": "60"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("before rotation")}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 2*time.Minute)
	if _, err := queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("after rotation")}); err != nil {
		t.Fatal(err)
	}
	current, err := owner.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: k.KeyId})
	if err != nil || aws.ToString(current.KeyMetadata.CurrentKeyMaterialId) == aws.ToString(k.CurrentKeyMaterialId) {
		t.Fatal("queue encryption did not observe automatic rotation", err)
	}
	_, access, secret := c.user(t, "test", "rotated-queue-reader")
	reader := c.sqs(access, secret, "")
	putUserPolicy(t, c.iam("test", "test", ""), "rotated-queue-reader", allow(`"sqs:ReceiveMessage"`, "*"))
	_, err = reader.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
	assertAPIError(t, err, "KMS.AccessDeniedException")
	putUserPolicy(t, c.iam("test", "test", ""), "rotated-queue-reader", allow(`["sqs:ReceiveMessage","kms:Decrypt"]`, "*"))
	response, err := reader.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
	if err != nil || len(response.Messages) != 2 {
		t.Fatal("delivery spanning material versions", err)
	}
	seen := map[string]bool{}
	for _, message := range response.Messages {
		seen[aws.ToString(message.Body)] = true
	}
	if !seen["before rotation"] || !seen["after rotation"] {
		t.Fatal("rotation lost queue payloads")
	}
}
