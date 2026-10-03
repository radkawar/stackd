package stackd_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// Preserve native windows, original receipts and empty completed replays.
// Elapsed time alone is not evidence that AWS re-evaluated KMS authority.
func TestSNSArchiveNativeEncryptedReceipts(t *testing.T) {
	for _, name := range []string{"archive_encryption", "archive_kms_cold", "archive_kms_deny"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile("../testdata/aws/sns/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Account, Region string
				Observations    []struct {
					awsNativeObservation
					Observed string
				}
				Receipts []struct {
					Queue   string
					Message sqstypes.Message
				}
			}
			awsDecodeJSON(t, data, &fixture)
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					base := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
					setup := snsAdmissionFixture{Account: fixture.Account, Region: fixture.Region, Observations: []awsNativeObservation{{Started: base.UnixMilli()}}}
					cloud, clients, source := admissionFixtureCloud(t, backend, setup)
					topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
					queues := clients.sqs(fixture.Account, "test", "")
					keys := clients.kmsRegion(fixture.Region, fixture.Account, "test", "")
					urls, subscriptions, keyIDs := map[string]string{}, map[string]string{}, map[string]string{}
					ciphertexts := map[string][]byte{}
					received := map[string][]sqstypes.Message{}
					var nativeStart time.Time
					beginnings := map[string]string{}
					type publication struct{ id, sequence, timestamp string }
					publications := map[string]publication{}
					for _, observation := range fixture.Observations {
						at, err := time.Parse(time.RFC3339Nano, observation.Observed)
						if err != nil {
							t.Fatal(err)
						}
						if nativeStart.IsZero() {
							nativeStart = at
						}
						if next := base.Add(at.Sub(nativeStart)); next.After(source.Now()) {
							if err := source.Advance(next.Sub(source.Now())); err != nil {
								t.Fatal(err)
							}
						}
						row := observation.awsNativeObservation
						if row.Service == "sts" || row.Service == "cloudtrail" || row.Operation == "delete-message" {
							continue
						}
						if row.Operation == "receive-message" {
							var input sqs.ReceiveMessageInput
							awsDecodeJSON(t, row.Input, &input)
							nativeURL := aws.ToString(input.QueueUrl)
							received[nativeURL] = append(received[nativeURL], snsAdmissionReceive(t, cloud, queues, aws.String(urls[nativeURL]))...)
							continue
						}
						prepare := func(input any) {
							switch in := input.(type) {
							case *sqs.GetQueueAttributesInput:
								in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
							case *sqs.SetQueueAttributesInput:
								in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
							case *sns.SetTopicAttributesInput:
								if aws.ToString(in.AttributeName) == "KmsMasterKeyId" {
									in.AttributeValue = aws.String(keyIDs[aws.ToString(in.AttributeValue)])
								}
							case *sns.SubscribeInput:
								if document, exists := in.Attributes["ReplayPolicy"]; exists {
									var policy map[string]string
									awsDecodeJSON(t, []byte(document), &policy)
									policy["StartingPoint"] = beginnings[aws.ToString(in.TopicArn)]
									encoded, err := json.Marshal(policy)
									if err != nil {
										t.Fatal(err)
									}
									in.Attributes["ReplayPolicy"] = string(encoded)
								}
							case *sns.GetSubscriptionAttributesInput:
								in.SubscriptionArn = aws.String(subscriptions[aws.ToString(in.SubscriptionArn)])
							case *kms.PutKeyPolicyInput:
								in.KeyId = aws.String(keyIDs[aws.ToString(in.KeyId)])
							case *kms.DisableKeyInput:
								in.KeyId = aws.String(keyIDs[aws.ToString(in.KeyId)])
							case *kms.EnableKeyInput:
								in.KeyId = aws.String(keyIDs[aws.ToString(in.KeyId)])
							case *kms.DescribeKeyInput:
								in.KeyId = aws.String(keyIDs[aws.ToString(in.KeyId)])
							case *kms.GetKeyPolicyInput:
								in.KeyId = aws.String(keyIDs[aws.ToString(in.KeyId)])
							case *kms.EncryptInput:
								in.KeyId = aws.String(keyIDs[aws.ToString(in.KeyId)])
							case *kms.DecryptInput:
								in.CiphertextBlob = ciphertexts[string(in.CiphertextBlob)]
								if in.KeyId != nil {
									in.KeyId = aws.String(keyIDs[aws.ToString(in.KeyId)])
								}
							}
						}
						var client any = topics
						if row.Service == "sqs" {
							client = queues
						} else if row.Service == "kms" {
							client = keys
						}
						if row.Operation == "get-subscription-attributes" {
							snsHTTPDrain(t, cloud)
						}
						output := snsControlReplay(t, client, row, prepare)
						switch out := output.(type) {
						case *sqs.CreateQueueOutput:
							var native sqs.CreateQueueOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							urls[aws.ToString(native.QueueUrl)] = aws.ToString(out.QueueUrl)
						case *kms.CreateKeyOutput:
							var native kms.CreateKeyOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							keyIDs[aws.ToString(native.KeyMetadata.KeyId)] = aws.ToString(out.KeyMetadata.KeyId)
							keyIDs[aws.ToString(native.KeyMetadata.Arn)] = aws.ToString(out.KeyMetadata.Arn)
						case *kms.EncryptOutput:
							var native kms.EncryptOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							ciphertexts[string(native.CiphertextBlob)] = out.CiphertextBlob
						case *kms.DecryptOutput:
							var native kms.DecryptOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							if !bytes.Equal(out.Plaintext, native.Plaintext) {
								t.Fatalf("%s owner key control changed plaintext", row.Label)
							}
						case *sns.GetTopicAttributesOutput:
							beginnings[out.Attributes["TopicArn"]] = out.Attributes["BeginningArchiveTime"]
						case *sns.SubscribeOutput:
							var native sns.SubscribeOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							subscriptions[aws.ToString(native.SubscriptionArn)] = aws.ToString(out.SubscriptionArn)
						case *sns.GetSubscriptionAttributesOutput:
							var native sns.GetSubscriptionAttributesOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							// Draining settles local work; native intermediate
							// polling states do not establish completion timing.
							if want := native.Attributes["ReplayStatus"]; want == "Completed" && out.Attributes["ReplayStatus"] != want {
								t.Fatalf("%s replay status: %q, want %q", row.Label, out.Attributes["ReplayStatus"], want)
							}
						case *sns.PublishOutput:
							var native sns.PublishOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							publications[aws.ToString(native.MessageId)] = publication{aws.ToString(out.MessageId), aws.ToString(out.SequenceNumber), source.Now().UTC().Format("2006-01-02T15:04:05.000Z")}
						}
					}
					expected := map[string]int{}
					for _, receipt := range fixture.Receipts {
						expected[receipt.Queue]++
					}
					for queue, messages := range received {
						if len(messages) != expected[queue] {
							t.Fatalf("encrypted archive destination %s received %d notifications, want %d", queue, len(messages), expected[queue])
						}
					}
					for _, receipt := range fixture.Receipts {
						actual := received[receipt.Queue]
						if len(actual) != 1 {
							t.Fatalf("encrypted archive destination %s received %d notifications, want one", receipt.Queue, len(actual))
						}
						var got, want map[string]any
						awsDecodeJSON(t, []byte(aws.ToString(actual[0].Body)), &got)
						awsDecodeJSON(t, []byte(aws.ToString(receipt.Message.Body)), &want)
						published := publications[want["MessageId"].(string)]
						want["MessageId"], want["SequenceNumber"], want["Timestamp"] = published.id, published.sequence, published.timestamp
						// The local public origin and generated subscription IDs differ;
						// optional-field presence and the rest of the envelope do not.
						if _, exists := want["UnsubscribeURL"]; exists {
							if _, present := got["UnsubscribeURL"]; !present {
								t.Fatal("notification omitted UnsubscribeURL")
							}
							delete(want, "UnsubscribeURL")
							delete(got, "UnsubscribeURL")
						}
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("encrypted original/replay envelope differs\ngot: %#v\nwant: %#v", got, want)
						}
					}
				})
			}
		})
	}
}
