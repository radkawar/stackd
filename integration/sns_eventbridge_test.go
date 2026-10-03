package stackd_test

import (
	"maps"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func TestEventBridgeNativeSNSPolicyContext(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/sns/eventbridge.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		snsAdmissionFixture
		Owned struct {
			Queues map[string]struct{ URL string }
		} `json:"owned_resources"`
		Deliveries []struct {
			Queue      string
			TargetARN  string `json:"target_arn"`
			Event      map[string]any
			Envelope   map[string]any
			Attributes map[string]sqstypes.MessageAttributeValue `json:"message_attributes"`
		}
	}
	awsDecodeJSON(t, data, &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, clients, source := admissionFixtureCloud(t, backend, fixture.snsAdmissionFixture)
			topics, queues := admissionSNSClient(clients, fixture.Account, fixture.Region), clients.sqs(fixture.Account, "test", "")
			events := eventDeliveryClient(clients, fixture.Account)
			urls, subscriptions := map[string]string{}, map[string]string{}
			var eventID string
			var accepted time.Time
			prepare := func(input any) {
				switch in := input.(type) {
				case *sqs.GetQueueAttributesInput:
					in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
				case *sqs.SetQueueAttributesInput:
					in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
				}
			}
		setup:
			for _, row := range fixture.Observations {
				var client any
				switch row.Service {
				case "sts":
					continue
				case "sns":
					client = topics
				case "sqs":
					client = queues
				case "events":
					client = events
				default:
					t.Fatalf("unhandled fixture service %s", row.Service)
				}
				if row.Operation == "put-events" {
					accepted = time.UnixMilli(row.Started).UTC()
					source.Advance(accepted.Sub(source.Now()))
				}
				out := snsControlReplay(t, client, row, prepare)
				switch result := out.(type) {
				case *sqs.CreateQueueOutput:
					var native sqs.CreateQueueOutput
					awsDecodeJSON(t, row.Result.Output, &native)
					urls[aws.ToString(native.QueueUrl)] = aws.ToString(result.QueueUrl)
				case *sns.SubscribeOutput:
					var input sns.SubscribeInput
					awsDecodeJSON(t, row.Input, &input)
					subscriptions[aws.ToString(input.TopicArn)] = aws.ToString(result.SubscriptionArn)
				case *eventbridge.PutTargetsOutput:
					if result.FailedEntryCount != 0 {
						t.Fatalf("native targets rejected: %+v", result)
					}
				case *eventbridge.PutEventsOutput:
					if result.FailedEntryCount != 0 || len(result.Entries) != 1 {
						t.Fatalf("native event rejected: %+v", result)
					}
					eventID = aws.ToString(result.Entries[0].EventId)
					break setup
				}
			}
			if out, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || out.More {
				t.Fatalf("delivery jobs did not settle: %+v, %v", out, err)
			}
			seen := map[string]bool{}
			for kind, queue := range fixture.Owned.Queues {
				for {
					out, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: aws.String(urls[queue.URL]), MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"}})
					if err != nil {
						t.Fatal(err)
					}
					if len(out.Messages) == 0 {
						break
					}
					for _, message := range out.Messages {
						var body map[string]any
						awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &body)
						event := body
						target := aws.ToString(message.MessageAttributes["TARGET_ARN"].StringValue)
						if topic, ok := body["TopicArn"].(string); ok {
							target = topic
							event = nil
							awsDecodeJSON(t, []byte(body["Message"].(string)), &event)
							snsVerifySignature(t, body, clients.server.URL, clients.server.URL)
						}
						matched := false
						for _, native := range fixture.Deliveries {
							if native.TargetARN != target || native.Queue != kind {
								continue
							}
							matched = true
							if seen[target] {
								t.Fatalf("target %s produced another receipt without advancing visibility time", target)
							}
							seen[target] = true
							wantEvent := maps.Clone(native.Event)
							wantEvent["id"], wantEvent["time"] = eventID, accepted.Format(time.RFC3339)
							if !reflect.DeepEqual(event, wantEvent) {
								t.Errorf("%s changed the native event\ngot: %v\nwant: %v", target, event, wantEvent)
							}
							wantAttributes := make(map[string]string, len(native.Attributes))
							for name, value := range native.Attributes {
								wantAttributes[name] = aws.ToString(value.StringValue)
							}
							assertEventDeliveryAttributes(t, message.MessageAttributes, wantAttributes, "events.amazonaws.com", "sns:Publish", target)
							if native.Envelope != nil {
								stamp, err := time.Parse(time.RFC3339Nano, body["Timestamp"].(string))
								if err != nil || !stamp.Equal(accepted) {
									t.Errorf("SNS did not use service acceptance time: %v, %v", stamp, err)
								}
								unsubscribe, err := url.Parse(body["UnsubscribeURL"].(string))
								if err != nil {
									t.Fatal(err)
								}
								if unsubscribe.Scheme+"://"+unsubscribe.Host != clients.server.URL || unsubscribe.Query().Get("Action") != "Unsubscribe" || unsubscribe.Query().Get("SubscriptionArn") != subscriptions[target] {
									t.Errorf("notification points to another subscription: %s", unsubscribe)
								}
								// Compare the complete native envelope after validating the
								// local body, signature, time and subscription identity.
								for _, field := range []string{"Message", "MessageId", "Timestamp", "Signature", "SigningCertURL", "UnsubscribeURL"} {
									body[field] = native.Envelope[field]
								}
								if !reflect.DeepEqual(body, native.Envelope) {
									t.Errorf("SNS envelope differs\ngot: %v\nwant: %v", body, native.Envelope)
								}
							}
							break
						}
						if !matched {
							t.Fatalf("unexpected %s receipt for %s: %s", kind, target, aws.ToString(message.Body))
						}
					}
				}
			}
			for _, native := range fixture.Deliveries {
				if !seen[native.TargetARN] {
					t.Errorf("native %s outcome missing for %s", native.Queue, native.TargetARN)
				}
			}
		})
	}
}
