package stackd_test

import (
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func TestSNSNativeRedriveAndRecovery(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/sns/delivery.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Captures map[string]struct {
			snsAdmissionFixture
			SupplementalMetricQueries []awsNativeObservation `json:"supplemental_metric_queries"`
		}
	}
	awsDecodeJSON(t, data, &fixture)
	for name, capture := range fixture.Captures {
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(name+"/"+backend, func(t *testing.T) {
				for _, limitation := range capture.Limitations {
					t.Log(limitation)
				}
				cloud, clients, source := admissionFixtureCloud(t, backend, capture.snsAdmissionFixture)
				topics, queues := admissionSNSClient(clients, capture.Account, capture.Region), clients.sqs(capture.Account, "test", "")
				urls, subscriptions, ids := map[string]string{}, map[string]string{}, map[string]string{}
				published := map[string]time.Time{}
				nativeReceipts, received := map[string][]sqstypes.Message{}, map[string][]sqstypes.Message{}
				raw := false
				prepare := func(input any) {
					switch in := input.(type) {
					case *sqs.GetQueueAttributesInput:
						in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
					case *sqs.SetQueueAttributesInput:
						in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
					case *sqs.DeleteQueueInput:
						in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
					case *sqs.ReceiveMessageInput:
						in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
						in.WaitTimeSeconds = 0
					case *sns.GetSubscriptionAttributesInput:
						in.SubscriptionArn = aws.String(subscriptions[aws.ToString(in.SubscriptionArn)])
					case *sns.UnsubscribeInput:
						in.SubscriptionArn = aws.String(subscriptions[aws.ToString(in.SubscriptionArn)])
					}
				}
				for _, row := range capture.Observations {
					// Native receives define bounded outcome windows, not an SNS
					// latency contract. Local receipts are acknowledged immediately;
					// native receipt handles never become local deletion inputs.
					if row.Service == "sts" || row.Operation == "delete-message" {
						continue
					}
					source.Advance(time.UnixMilli(row.Started).Sub(source.Now()))
					if out, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || out.More {
						t.Fatalf("SNS delivery jobs did not settle: %+v, %v", out, err)
					}
					var client any
					switch row.Service {
					case "sns":
						client = topics
					case "sqs":
						client = queues
					default:
						t.Fatalf("unhandled fixture service %s", row.Service)
					}
					out := snsControlReplay(t, client, row, prepare)
					switch result := out.(type) {
					case *sqs.CreateQueueOutput:
						var native sqs.CreateQueueOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						urls[aws.ToString(native.QueueUrl)] = aws.ToString(result.QueueUrl)
					case *sns.SubscribeOutput:
						var native sns.SubscribeOutput
						var input sns.SubscribeInput
						awsDecodeJSON(t, row.Result.Output, &native)
						awsDecodeJSON(t, row.Input, &input)
						subscriptions[aws.ToString(native.SubscriptionArn)] = aws.ToString(result.SubscriptionArn)
						raw = input.Attributes["RawMessageDelivery"] == "true"
					case *sns.PublishOutput:
						var native sns.PublishOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						id := aws.ToString(result.MessageId)
						ids[id], published[id] = aws.ToString(native.MessageId), source.Now()
					case *sqs.ReceiveMessageOutput:
						var native sqs.ReceiveMessageOutput
						var input sqs.ReceiveMessageInput
						awsDecodeJSON(t, row.Result.Output, &native)
						awsDecodeJSON(t, row.Input, &input)
						queue := aws.ToString(input.QueueUrl)
						nativeReceipts[queue] = append(nativeReceipts[queue], native.Messages...)
						received[queue] = append(received[queue], result.Messages...)
						for _, message := range result.Messages {
							if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: aws.String(urls[queue]), ReceiptHandle: message.ReceiptHandle}); err != nil {
								t.Fatal(err)
							}
						}
					}
				}
				for queue, wanted := range nativeReceipts {
					actual := received[queue]
					if len(actual) != len(wanted) {
						t.Errorf("%s: got %d receipts in the captured windows, want %d", queue, len(actual), len(wanted))
					}
					for _, native := range wanted {
						var nativeNotification snsMetricNotification
						if !raw {
							awsDecodeJSON(t, []byte(aws.ToString(native.Body)), &nativeNotification)
						}
						matched := false
						for _, message := range actual {
							var notification snsMetricNotification
							if raw {
								if aws.ToString(message.Body) != aws.ToString(native.Body) {
									continue
								}
								if aws.ToString(message.MD5OfBody) != aws.ToString(native.MD5OfBody) || aws.ToString(message.MD5OfMessageAttributes) != aws.ToString(native.MD5OfMessageAttributes) {
									t.Errorf("raw native consumer digests differ: %+v", message)
								}
							} else {
								awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &notification)
								if ids[notification.MessageId] != nativeNotification.MessageId {
									continue
								}
								var envelope, nativeEnvelope map[string]any
								awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &envelope)
								awsDecodeJSON(t, []byte(aws.ToString(native.Body)), &nativeEnvelope)
								snsVerifySignature(t, envelope, clients.server.URL, clients.server.URL)
								stamp, err := time.Parse(time.RFC3339Nano, envelope["Timestamp"].(string))
								if err != nil || !stamp.Equal(published[notification.MessageId]) {
									t.Errorf("redrive changed the original publication time: %v, %v", stamp, err)
								}
								unsubscribe, err := url.Parse(envelope["UnsubscribeURL"].(string))
								if err != nil {
									t.Fatal(err)
								}
								nativeUnsubscribe, err := url.Parse(nativeEnvelope["UnsubscribeURL"].(string))
								if err != nil {
									t.Fatal(err)
								}
								if unsubscribe.Scheme+"://"+unsubscribe.Host != clients.server.URL || unsubscribe.Query().Get("Action") != "Unsubscribe" || unsubscribe.Query().Get("SubscriptionArn") != subscriptions[nativeUnsubscribe.Query().Get("SubscriptionArn")] {
									t.Errorf("redrive points to a different subscription: %s", unsubscribe)
								}
								notification.MessageId = nativeNotification.MessageId
								if !reflect.DeepEqual(notification, nativeNotification) {
									got, _ := json.Marshal(notification)
									want, _ := json.Marshal(nativeNotification)
									t.Errorf("native redrive envelope differs\ngot: %s\nwant: %s", got, want)
								}
							}
							if !reflect.DeepEqual(message.MessageAttributes, native.MessageAttributes) {
								t.Errorf("native SQS message attributes differ\ngot: %+v\nwant: %+v", message.MessageAttributes, native.MessageAttributes)
							}
							matched = true
							break
						}
						if !matched {
							t.Errorf("native %s receipt missing: %s", queue, aws.ToString(native.Body))
						}
					}
				}
				source.Advance(time.Minute)
				if out, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || out.More {
					t.Fatalf("retained SNS metrics did not flush: %+v, %v", out, err)
				}
				metrics := metricsClient(clients, capture.Account)
				for _, row := range capture.SupplementalMetricQueries {
					t.Run(row.Label, func(t *testing.T) {
						out := snsControlReplay(t, metrics, row)
						assertMetricData(t, out.(*cloudwatch.GetMetricDataOutput), row.Result.Output)
					})
				}
			})
		}
	}
}
