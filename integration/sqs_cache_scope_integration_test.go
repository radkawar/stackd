package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

func TestSQSKeyCacheRequesterScopeMatchesAWS(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			data, err := os.ReadFile("../testdata/aws/sqs/cache_scope.json")
			if err != nil {
				t.Fatal(err)
			}
			manual := clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
			var c cloudClients
			if backend == "sqlite" {
				c, _ = openSQLiteCloud(t, filepath.Join(t.TempDir(), "sqs.sqlite"), storage.NewMemory(), manual)
			} else {
				c = clockCloud(t, stackd.Config{Clock: manual})
			}
			root, owner, queues := c.iam("test", "test", ""), c.kms("test", "test", ""), c.sqs("test", "test", "")
			key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			// Keep names, policy scope and operation order from the capture. Only the
			// account and generated key identifier differ in the local stack.
			data = []byte(strings.NewReplacer("111111111111", "000000000000", "<key>", aws.ToString(key.KeyMetadata.KeyId)).Replace(string(data)))
			var capture struct {
				Completed bool
				Sessions  map[string]struct {
					Name  string
					Scope sts.AssumeRoleInput
				}
				Observations []struct {
					Case, Caller, Service, Operation string
					Error                            *struct{ Code string }
					Output                           struct{ Messages []struct{ Body string } }
				}
			}
			if err := json.Unmarshal(data, &capture); err != nil || !capture.Completed {
				t.Fatal("native capture is incomplete", err)
			}
			urls := make(map[string]*string)
			for _, name := range []string{"warm", "fresh"} {
				queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("cache-worker-" + name), Attributes: map[string]string{"KmsMasterKeyId": aws.ToString(key.KeyMetadata.Arn), "KmsDataKeyReusePeriodSeconds": "300", "VisibilityTimeout": "0"}})
				if err != nil {
					t.Fatal(err)
				}
				urls[name] = queue.QueueUrl
			}
			role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("cache-worker"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":["sts:AssumeRole","sts:TagSession","sts:SetSourceIdentity"]}}`)})
			if err != nil {
				t.Fatal(err)
			}
			var base struct {
				Version   string
				Statement []json.RawMessage
			}
			if err := json.Unmarshal([]byte(aws.ToString(capture.Sessions["inline_allowed"].Scope.Policy)), &base); err != nil {
				t.Fatal(err)
			}
			for _, condition := range []string{`{"StringLike":{"aws:userid":"*:name-denied"}}`, `{"StringEquals":{"aws:PrincipalTag/kms":"denied"}}`, `{"StringEquals":{"aws:SourceIdentity":"denied"}}`} {
				base.Statement = append(base.Statement, json.RawMessage(fmt.Sprintf(`{"Effect":"Deny","Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":%q,"Condition":%s}`, aws.ToString(key.KeyMetadata.Arn), condition)))
			}
			document, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			putRolePolicy(t, root, "cache-worker", string(document))
			for _, name := range []string{"allowed", "limited"} {
				if _, err := root.CreatePolicy(t.Context(), &iam.CreatePolicyInput{PolicyName: aws.String("cache-worker-" + name), PolicyDocument: capture.Sessions["inline_"+name].Scope.Policy}); err != nil {
					t.Fatal(err)
				}
			}
			sessions := make(map[string]*ststypes.Credentials)
			for name, captured := range capture.Sessions {
				input := captured.Scope
				input.RoleArn, input.RoleSessionName = role.Role.Arn, &captured.Name
				assumed, err := c.sts("test", "test", "").AssumeRole(t.Context(), &input)
				if err != nil {
					t.Fatal(name, err)
				}
				sessions[name] = assumed.Credentials
			}
			sent := map[string]map[string]bool{"warm": {}, "fresh": {"owner seeded": true}}
			for _, row := range capture.Observations {
				if row.Case == "name_denied_fresh_seeded_receive" {
					if _, err := queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: urls["fresh"], MessageBody: aws.String("owner seeded")}); err != nil {
						t.Fatal(err)
					}
				}
				name := "warm"
				if strings.Contains(row.Case, "_fresh") {
					name = "fresh"
				}
				queue := urls[name]
				t.Run(row.Case, func(t *testing.T) {
					var err error
					switch row.Operation {
					case "generate-data-key":
						_, err = c.sessionKMS(sessions[row.Caller]).GenerateDataKey(t.Context(), &kms.GenerateDataKeyInput{KeyId: key.KeyMetadata.KeyId, KeySpec: kmstypes.DataKeySpecAes256})
					case "send-message":
						body := strings.TrimSuffix(row.Case, "_send")
						_, err = c.sessionSQS(sessions[row.Caller]).SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue, MessageBody: &body})
						if err == nil {
							sent[name][body] = true
						}
					case "receive-message":
						var output *sqs.ReceiveMessageOutput
						output, err = c.sessionSQS(sessions[row.Caller]).ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue, VisibilityTimeout: 0})
						if err == nil && row.Error == nil && len(output.Messages) != len(row.Output.Messages) {
							t.Fatalf("received %d messages, native received %d", len(output.Messages), len(row.Output.Messages))
						}
						if err == nil {
							for _, message := range output.Messages {
								if !sent[name][aws.ToString(message.Body)] {
									t.Fatal("decryption returned an unsent body", message.Body)
								}
							}
						}
					default:
						t.Fatal("unhandled captured operation", row.Operation)
					}
					if row.Error != nil {
						assertAPIError(t, err, row.Error.Code)
					} else if err != nil {
						t.Fatal("AWS allowed the operation", err)
					}
				})
			}
			// A shared cached key does not extend permission beyond the configured
			// reuse period. Expiry rechecks both producer and consumer KMS access.
			advanceClock(t, manual, 5*time.Minute)
			for _, name := range []string{"name_denied", "tag_denied", "source_denied"} {
				client := c.sessionSQS(sessions[name])
				_, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: urls["warm"], MessageBody: aws.String("expired")})
				assertAPIError(t, err, "KMS.AccessDeniedException")
				_, err = client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: urls["warm"], VisibilityTimeout: 0})
				assertAPIError(t, err, "KMS.AccessDeniedException")
			}
		})
	}
}
