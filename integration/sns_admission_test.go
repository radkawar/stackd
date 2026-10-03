package stackd_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

type snsAdmissionFixture struct {
	Account, Region string
	Limitations     []string
	Observations    []awsNativeObservation
}

type snsAdmissionAttribute struct{ Type, Value string }

type snsAdmissionNotification struct {
	Type, MessageId, TopicArn, Message string
	Subject                            *string
	MessageAttributes                  map[string]snsAdmissionAttribute
	QueueGroupID                       string `json:"-"`
}

func admissionSNSClient(c cloudClients, account, region string) *sns.Client {
	return c.snsRegion(region, account, "test", "")
}

func admissionFixtureCloud(t *testing.T, backend string, fixture snsAdmissionFixture) (*stackd.Stack, cloudClients, *clock.Manual) {
	t.Helper()
	backends := storage.NewMemory()
	if backend == "sqlite" {
		backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "sns-admission.sqlite"))
	}
	source := clock.NewManual(time.UnixMilli(fixture.Observations[0].Started).UTC())
	cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
	return cloud, clients, source
}

func TestSNSNativeAdmission(t *testing.T) {
	for _, filename := range []string{"admission", "numeric_attributes", "attribute_unicode", "message_groups"} {
		data, err := os.ReadFile("../testdata/aws/sns/" + filename + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var fixture snsAdmissionFixture
		awsDecodeJSON(t, data, &fixture)
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(filename+"/"+backend, func(t *testing.T) {
				for _, limitation := range fixture.Limitations {
					t.Log(limitation)
				}
				cloud, clients, source := admissionFixtureCloud(t, backend, fixture)
				topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
				queues := clients.sqs(fixture.Account, "test", "")
				// These real dependencies isolate replay; only resource identities in
				// captured publication/subscription inputs are rebound below.
				topic, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: aws.String("native-admission")})
				if err != nil {
					t.Fatal(err)
				}
				queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("native-admission")})
				if err != nil {
					t.Fatal(err)
				}
				attrs, err := queues.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: queue.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
				if err != nil {
					t.Fatal(err)
				}
				queueARN := attrs.Attributes["QueueArn"]
				policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, queueARN, aws.ToString(topic.TopicArn))
				if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
					t.Fatal(err)
				}
				var subscription *string
				capturedSubscription := false
				for _, row := range fixture.Observations {
					if row.Service == "sns" && row.Operation == "subscribe" {
						capturedSubscription = true
						break
					}
				}
				if !capturedSubscription {
					out, err := topics.Subscribe(t.Context(), &sns.SubscribeInput{TopicArn: topic.TopicArn, Protocol: aws.String("sqs"), Endpoint: &queueARN, ReturnSubscriptionArn: true})
					if err != nil {
						t.Fatal(err)
					}
					subscription = out.SubscriptionArn
				}
				// Native notifications are indexed by their publication IDs, not
				// SQS receive order, random local IDs, or native receive grouping.
				nativeNotifications := map[string]snsAdmissionNotification{}
				nativeQueueMessages := map[string]sqstypes.Message{}
				for _, row := range fixture.Observations {
					if row.Operation != "receive-message" {
						continue
					}
					var out sqs.ReceiveMessageOutput
					awsDecodeJSON(t, row.Result.Output, &out)
					for _, message := range out.Messages {
						nativeQueueMessages[aws.ToString(message.MessageId)] = message
						var notification snsAdmissionNotification
						if json.Unmarshal([]byte(aws.ToString(message.Body)), &notification) == nil && notification.TopicArn != "" {
							notification.QueueGroupID = message.Attributes["MessageGroupId"]
							nativeNotifications[notification.MessageId] = notification
						}
					}
				}
				if len(nativeNotifications) == 0 {
					nativeNotifications = nil
				}
				var acceptedProbe *awsNativeObservation
				for _, row := range fixture.Observations {
					// Admission capture ends here; subsequent observations verify
					// native resource cleanup, not publication behavior.
					if row.Operation == "unsubscribe" {
						break
					}
					if row.Service != "sns" && row.Operation != "send-message" {
						continue
					}
					switch row.Operation {
					case "publish", "publish-batch", "send-message", "subscribe", "get-subscription-attributes":
					default:
						continue // Other rows retain native setup/cleanup evidence.
					}
					if !t.Run(row.Label, func(t *testing.T) {
						advanceClock(t, source, time.Millisecond)
						switch row.Operation {
						case "subscribe":
							var in sns.SubscribeInput
							awsDecodeJSON(t, row.Input, &in)
							in.TopicArn, in.Endpoint = topic.TopicArn, &queueARN
							out, err := topics.Subscribe(t.Context(), &in)
							awsNativeResult(t, row, err)
							if err == nil {
								subscription = out.SubscriptionArn
							}
							if err != nil && acceptedProbe != nil {
								// A rejected conflicting Subscribe must not change the
								// next consumer delivery to raw or install its filter.
								snsAdmissionPublish(t, cloud, topics, queues, topic.TopicArn, queue.QueueUrl, *acceptedProbe, nativeNotifications)
							}
						case "get-subscription-attributes":
							out, err := topics.GetSubscriptionAttributes(t.Context(), &sns.GetSubscriptionAttributesInput{SubscriptionArn: subscription})
							awsNativeResult(t, row, err)
							var native sns.GetSubscriptionAttributesOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							// Compare the attributes whose rejected updates would
							// alter delivery, not unrelated incidental defaults.
							for _, key := range []string{"RawMessageDelivery", "FilterPolicy"} {
								got, gotExists := out.Attributes[key]
								want, wantExists := native.Attributes[key]
								if got != want || gotExists != wantExists {
									t.Fatalf("%s: got %q (present %v), native %q (present %v)", key, got, gotExists, want, wantExists)
								}
							}
						case "publish", "publish-batch":
							snsAdmissionPublish(t, cloud, topics, queues, topic.TopicArn, queue.QueueUrl, row, nativeNotifications)
							if row.Operation == "publish" && row.Result.Code == "Success" && acceptedProbe == nil {
								saved := row
								acceptedProbe = &saved
							}
						case "send-message":
							var in sqs.SendMessageInput
							awsDecodeJSON(t, row.Input, &in)
							in.QueueUrl = queue.QueueUrl
							out, err := queues.SendMessage(t.Context(), &in)
							awsNativeResult(t, row, err)
							messages := snsAdmissionReceive(t, cloud, queues, queue.QueueUrl)
							if err != nil {
								if len(messages) != 0 {
									t.Fatalf("rejected SQS number delivered: %v", messages)
								}
								return
							}
							if len(messages) != 1 || aws.ToString(messages[0].MessageId) != aws.ToString(out.MessageId) || aws.ToString(messages[0].Body) != aws.ToString(in.MessageBody) {
								t.Fatalf("accepted SQS publication not consumed intact: %v", messages)
							}
							var native sqs.SendMessageOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							if aws.ToString(out.MD5OfMessageAttributes) != aws.ToString(native.MD5OfMessageAttributes) {
								t.Fatalf("submitted attribute checksum: got %s, native %s", aws.ToString(out.MD5OfMessageAttributes), aws.ToString(native.MD5OfMessageAttributes))
							}
							receipt, ok := nativeQueueMessages[aws.ToString(native.MessageId)]
							if !ok {
								t.Fatalf("missing native SQS receipt for %s", row.Label)
							}
							if !reflect.DeepEqual(messages[0].MessageAttributes, receipt.MessageAttributes) || aws.ToString(messages[0].MD5OfMessageAttributes) != aws.ToString(receipt.MD5OfMessageAttributes) {
								t.Fatalf("consumed attributes: got %+v, native %+v", messages[0].MessageAttributes, receipt.MessageAttributes)
							}
						}
					}) {
						t.FailNow()
					}
				}
			})
		}
	}
}

func snsAdmissionPublish(t *testing.T, cloud *stackd.Stack, topics *sns.Client, queues *sqs.Client, topicARN, queueURL *string, row awsNativeObservation, nativeNotifications map[string]snsAdmissionNotification) {
	t.Helper()
	wanted := map[string]snsAdmissionNotification{}
	if row.Operation == "publish" {
		var in sns.PublishInput
		awsDecodeJSON(t, row.Input, &in)
		in.TopicArn = topicARN
		out, err := topics.Publish(t.Context(), &in)
		awsNativeResult(t, row, err)
		if err == nil {
			var native sns.PublishOutput
			awsDecodeJSON(t, row.Result.Output, &native)
			notification, captured := nativeNotifications[aws.ToString(native.MessageId)]
			if !captured {
				if nativeNotifications != nil {
					t.Fatalf("missing native notification for accepted publication %q", row.Label)
				}
				// Numeric boundary captures prove admission only. This local
				// consumer check generalizes the spelling observed in admission.json.
				notification = snsAdmissionNotification{Type: "Notification", Message: aws.ToString(in.Message), Subject: in.Subject}
				if len(in.MessageAttributes) != 0 {
					notification.MessageAttributes = map[string]snsAdmissionAttribute{}
				}
				for name, attribute := range in.MessageAttributes {
					notification.MessageAttributes[name] = snsAdmissionAttribute{Type: aws.ToString(attribute.DataType), Value: aws.ToString(attribute.StringValue)}
				}
			}
			wanted[aws.ToString(out.MessageId)] = notification
		}
	} else {
		var in sns.PublishBatchInput
		awsDecodeJSON(t, row.Input, &in)
		in.TopicArn = topicARN
		out, err := topics.PublishBatch(t.Context(), &in)
		awsNativeResult(t, row, err)
		if err == nil {
			var native sns.PublishBatchOutput
			awsDecodeJSON(t, row.Result.Output, &native)
			type failure struct {
				Code        string
				SenderFault bool
			}
			gotFailed, wantFailed := map[string]failure{}, map[string]failure{}
			for _, entry := range out.Failed {
				gotFailed[aws.ToString(entry.Id)] = failure{aws.ToString(entry.Code), entry.SenderFault}
			}
			for _, entry := range native.Failed {
				wantFailed[aws.ToString(entry.Id)] = failure{aws.ToString(entry.Code), entry.SenderFault}
			}
			if len(out.Failed) != len(gotFailed) || !maps.Equal(gotFailed, wantFailed) {
				t.Fatalf("batch entry failures: got %v, native %v", gotFailed, wantFailed)
			}
			remaining := map[string]string{}
			for _, entry := range native.Successful {
				remaining[aws.ToString(entry.Id)] = aws.ToString(entry.MessageId)
			}
			for _, entry := range out.Successful {
				id := aws.ToString(entry.Id)
				nativeID, ok := remaining[id]
				if !ok {
					t.Fatalf("unexpected successful batch entry %q", id)
				}
				notification, ok := nativeNotifications[nativeID]
				if !ok {
					t.Fatalf("missing native receipt for successful batch entry %q", id)
				}
				wanted[aws.ToString(entry.MessageId)] = notification
				delete(remaining, id)
			}
			if len(remaining) != 0 {
				t.Fatalf("native accepted batch entries missing: %v", remaining)
			}
		}
	}
	for _, message := range snsAdmissionReceive(t, cloud, queues, queueURL) {
		var got snsAdmissionNotification
		awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &got)
		want, ok := wanted[got.MessageId]
		if !ok {
			t.Fatalf("unaccepted or duplicate SNS delivery: %+v", got)
		}
		if got.Type != want.Type || got.Message != want.Message || got.TopicArn != aws.ToString(topicARN) || (got.Subject == nil) != (want.Subject == nil) || aws.ToString(got.Subject) != aws.ToString(want.Subject) || !maps.Equal(got.MessageAttributes, want.MessageAttributes) {
			t.Fatalf("consumed notification differs from native publication: got %+v, want %+v", got, want)
		}
		group, grouped := message.Attributes["MessageGroupId"]
		if group != want.QueueGroupID || grouped != (want.QueueGroupID != "") {
			t.Fatalf("consumer group differs from native: got %q (present %v), want %q", group, grouped, want.QueueGroupID)
		}
		delete(wanted, got.MessageId)
	}
	if len(wanted) != 0 {
		t.Fatalf("accepted SNS publications not delivered: %v", wanted)
	}
}

func snsAdmissionReceive(t *testing.T, cloud *stackd.Stack, queues *sqs.Client, queueURL *string) []sqstypes.Message {
	t.Helper()
	if result, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || result.More {
		t.Fatalf("SNS deliveries did not settle: %+v, %v", result, err)
	}
	var messages []sqstypes.Message
	for {
		out, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queueURL, MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"}, MessageSystemAttributeNames: []sqstypes.MessageSystemAttributeName{sqstypes.MessageSystemAttributeNameAll}})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Messages) == 0 {
			return messages
		}
		for _, message := range out.Messages {
			messages = append(messages, message)
			if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: queueURL, ReceiptHandle: message.ReceiptHandle}); err != nil {
				t.Fatal(err)
			}
		}
	}
}
