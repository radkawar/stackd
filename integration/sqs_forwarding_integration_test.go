package stackd_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func TestSQSForwardedKMSMatchesNativeConditions(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/sqs/forwarding.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Conditions   map[string]json.RawMessage `json:"deny_conditions"`
		Observations []struct {
			Case   string
			Error  *struct{ Code string }
			Output struct{ Messages []sqstypes.Message }
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"last", "via", "principal"} {
		t.Run(name, func(t *testing.T) {
			c := newCloudClients(t)
			owner, queues := c.kms("test", "test", ""), c.sqs("test", "test", "")
			_, access, secret := c.user(t, "test", "forwarded-worker")
			putUserPolicy(t, c.iam("test", "test", ""), "forwarded-worker", `{"Statement":{"Effect":"Allow","Action":["kms:GenerateDataKey","kms:Decrypt","sqs:SendMessage","sqs:ReceiveMessage"],"Resource":"*"}}`)
			caller, delivery := c.kms(access, secret, ""), c.sqs(access, secret, "")
			key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			document := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Deny","Principal":"*","Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*","Condition":%s}]}`, capture.Conditions[name])
			if _, err := owner.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: key.KeyMetadata.KeyId, Policy: &document}); err != nil {
				t.Fatal(err)
			}
			queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("forwarded"), Attributes: map[string]string{"KmsMasterKeyId": aws.ToString(key.KeyMetadata.Arn)}})
			if err != nil {
				t.Fatal(err)
			}
			compared := 0
			for _, observation := range capture.Observations {
				switch observation.Case {
				case "kms_" + name + "_direct":
					_, err := caller.GenerateDataKey(t.Context(), &kms.GenerateDataKeyInput{KeyId: key.KeyMetadata.KeyId, KeySpec: kmstypes.DataKeySpecAes256})
					if observation.Error == nil {
						t.Fatal("native direct KMS call was unexpectedly permitted")
					}
					assertAPIError(t, err, observation.Error.Code)
					compared++
				case "kms_" + name + "_send":
					_, err := delivery.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("encrypted")})
					if observation.Error != nil {
						// Smithy's AWSQueryError trait maps native CLI code
						// KMS.AccessDeniedException to the SDK's KmsAccessDenied.
						var denied *sqstypes.KmsAccessDenied
						if observation.Error.Code != "KMS.AccessDeniedException" || !errors.As(err, &denied) {
							t.Fatalf("send=%v, native=%v", err, observation.Error)
						}
					} else if err != nil {
						t.Fatal("forwarded KMS call was denied", err)
					}
					compared++
				case "kms_" + name + "_receive":
					got, err := delivery.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
					if err != nil || len(got.Messages) != len(observation.Output.Messages) || len(got.Messages) != 1 || aws.ToString(got.Messages[0].Body) != aws.ToString(observation.Output.Messages[0].Body) {
						t.Fatalf("encrypted delivery=%v %v, native=%v", got, err, observation.Output)
					}
					compared++
				}
			}
			want := 3
			if name == "principal" {
				want = 2
			}
			if compared != want {
				t.Fatalf("compared %d native cases, want %d", compared, want)
			}
		})
	}
}
