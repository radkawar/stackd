package stackd_test

import (
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/google/uuid"

	"stackd"
	"stackd/clock"
)

func TestSNSNativeRegionalSQS(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/sns/regional_sqs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Account      string
		SourceRegion string `json:"source_region"`
		Observations []struct {
			awsNativeObservation
			Region   string
			Observed time.Time
		}
		Receipts []struct {
			Region, Destination string
			Message             sqstypes.Message
		}
		Limitations []string
	}
	awsDecodeJSON(t, data, &fixture)
	if len(fixture.Observations) == 0 || len(fixture.Receipts) == 0 {
		t.Fatal("regional capture has no observations or native receipts")
	}
	for _, limitation := range fixture.Limitations {
		t.Log(limitation)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			start := fixture.Observations[0].Observed.Truncate(time.Millisecond)
			source := clock.NewManual(start)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			cloud := func() *stackd.Stack { return clients.server.Config.Handler.(*stackd.Stack) }
			queues := func(region, account string) *sqs.Client {
				options := clients.sqs(account, "test", "").Options()
				options.Region = region
				return sqs.New(options)
			}
			used, enabled := map[string]bool{}, map[string]bool{}
			for _, row := range fixture.Observations {
				used[row.Region] = true
			}
			// Native account reads are evidence only. Enable just the captured,
			// already-enabled opt-in Regions on this disposable local account.
			for _, row := range fixture.Observations {
				if row.Service != "account" || row.Operation != "list-regions" {
					continue
				}
				var native struct {
					Regions []struct{ RegionName, RegionOptStatus string }
				}
				awsDecodeJSON(t, row.Result.Output, &native)
				for _, region := range native.Regions {
					if used[region.RegionName] && !enabled[region.RegionName] && region.RegionOptStatus == "ENABLED" {
						enableAccountRegion(t, clients, source, fixture.Account, region.RegionName)
						enabled[region.RegionName] = true
					}
				}
			}
			offset := source.Now().Sub(start)
			type queueIdentity struct{ region, name string }
			identities := map[string]queueIdentity{}
			urls, subscriptions, ids, sequences := map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}
			published := map[string]time.Time{}
			origins := map[string]bool{clients.server.URL: true}
			nativeReceipts := map[string]sqstypes.Message{}
			for _, receipt := range fixture.Receipts {
				if !strings.HasPrefix(receipt.Destination, "arn:aws:sqs:"+receipt.Region+":"+fixture.Account+":") {
					t.Fatalf("native receipt has inconsistent destination scope: %s", receipt.Destination)
				}
				nativeReceipts[aws.ToString(receipt.Message.MessageId)] = receipt.Message
			}
			actual, wanted := map[string][]sqstypes.Message{}, map[string][]sqstypes.Message{}
			compareWindow := func() {
				t.Helper()
				for queue, expected := range wanted {
					messages := actual[queue]
					if len(messages) != len(expected) {
						t.Fatalf("%s: captured receive window got %d messages, native %d", queue, len(messages), len(expected))
					}
					for _, native := range expected {
						var want map[string]any
						wrapped := json.Unmarshal([]byte(aws.ToString(native.Body)), &want) == nil && want["Type"] == "Notification"
						match := -1
						for i, message := range messages {
							if wrapped {
								var got map[string]any
								awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &got)
								id, _ := got["MessageId"].(string)
								if ids[id] != want["MessageId"] {
									continue
								}
								stamp, parseErr := time.Parse(time.RFC3339Nano, got["Timestamp"].(string))
								if parseErr != nil || !stamp.Equal(published[id]) {
									t.Fatalf("regional delivery changed publication time: %v, %v", stamp, parseErr)
								}
								unsubscribe, parseErr := url.Parse(got["UnsubscribeURL"].(string))
								if parseErr != nil {
									t.Fatal(parseErr)
								}
								nativeURL, parseErr := url.Parse(want["UnsubscribeURL"].(string))
								if parseErr != nil {
									t.Fatal(parseErr)
								}
								origin := unsubscribe.Scheme + "://" + unsubscribe.Host
								if !origins[origin] || unsubscribe.Query().Get("Action") != "Unsubscribe" || unsubscribe.Query().Get("SubscriptionArn") != subscriptions[nativeURL.Query().Get("SubscriptionArn")] {
									t.Fatalf("regional delivery changed source subscription: %s", unsubscribe)
								}
								if _, signed := want["Signature"]; signed {
									snsVerifySignature(t, got, origin, clients.server.URL)
									got["Signature"], got["SigningCertURL"] = want["Signature"], want["SigningCertURL"]
								}
								if sequence, fifo := want["SequenceNumber"]; fifo {
									if got["SequenceNumber"] != sequences[id] {
										t.Fatal("regional delivery changed SNS sequence number")
									}
									got["SequenceNumber"] = sequence
								}
								got["MessageId"], got["Timestamp"], got["UnsubscribeURL"] = want["MessageId"], want["Timestamp"], want["UnsubscribeURL"]
								if !reflect.DeepEqual(got, want) {
									t.Fatalf("regional notification differs from native\ngot: %#v\nwant: %#v", got, want)
								}
							} else {
								if aws.ToString(message.Body) != aws.ToString(native.Body) {
									continue
								}
								if aws.ToString(message.MD5OfBody) != aws.ToString(native.MD5OfBody) {
									t.Fatal("raw regional body checksum differs")
								}
							}
							if !reflect.DeepEqual(message.MessageAttributes, native.MessageAttributes) || aws.ToString(message.MD5OfMessageAttributes) != aws.ToString(native.MD5OfMessageAttributes) {
								t.Fatalf("regional SQS attributes differ: got %+v, native %+v", message.MessageAttributes, native.MessageAttributes)
							}
							for _, key := range []string{"MessageGroupId", "MessageDeduplicationId"} {
								got, present := message.Attributes[key]
								want, exists := native.Attributes[key]
								if got != want || present != exists {
									t.Fatalf("%s: got %q (%v), native %q (%v)", key, got, present, want, exists)
								}
							}
							if _, fifo := native.Attributes["SequenceNumber"]; fifo {
								if n, ok := new(big.Int).SetString(message.Attributes["SequenceNumber"], 10); !ok || n.Sign() <= 0 {
									t.Fatal("FIFO SQS receipt has no valid sequence number")
								}
							}
							match = i
							break
						}
						if match < 0 {
							t.Fatalf("missing native regional receipt: %s", aws.ToString(native.Body))
						}
						messages = append(messages[:match], messages[match+1:]...)
					}
				}
				actual, wanted = map[string][]sqstypes.Message{}, map[string][]sqstypes.Message{}
			}
			reopenCloud := func() {
				t.Helper()
				clients = reopen()
				origins[clients.server.URL] = true
				for native, identity := range identities {
					out, err := queues(identity.region, fixture.Account).GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: &identity.name})
					if err != nil {
						t.Fatal(err)
					}
					urls[native] = aws.ToString(out.QueueUrl)
				}
			}
			firstPublish := true
			for _, row := range fixture.Observations {
				if row.Service == "sts" || row.Service == "account" || row.Operation == "delete-message" {
					continue
				}
				if row.Operation != "receive-message" {
					compareWindow()
				}
				at := row.Observed.Truncate(time.Millisecond).Add(offset)
				if at.After(source.Now()) {
					advanceClock(t, source, at.Sub(source.Now()))
				}
				if row.Operation == "publish" && firstPublish {
					// Reopen the real stores with regional subscriptions already accepted.
					reopenCloud()
					firstPublish = false
				}
				if !t.Run(row.Label, func(t *testing.T) {
					if row.Operation == "receive-message" {
						var in sqs.ReceiveMessageInput
						var native sqs.ReceiveMessageOutput
						awsDecodeJSON(t, row.Input, &in)
						awsDecodeJSON(t, row.Result.Output, &native)
						queue := aws.ToString(in.QueueUrl)
						for _, receipt := range native.Messages {
							if _, ok := nativeReceipts[aws.ToString(receipt.MessageId)]; !ok {
								t.Fatal("receive observation lacks captured receipt")
							}
						}
						// Poll grouping and network latency are not native contracts. Drain
						// each captured window, but compare before any policy repair/publish.
						wanted[queue] = append(wanted[queue], native.Messages...)
						actual[queue] = append(actual[queue], snsAdmissionReceive(t, cloud(), queues(row.Region, fixture.Account), aws.String(urls[queue]))...)
						return
					}
					var client any = admissionSNSClient(clients, fixture.Account, row.Region)
					if row.Service == "sqs" {
						client = queues(row.Region, fixture.Account)
					}
					out := snsControlReplay(t, client, row.awsNativeObservation, func(input any) {
						switch in := input.(type) {
						case *sqs.GetQueueAttributesInput:
							in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
						case *sqs.SetQueueAttributesInput:
							in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
						case *sns.GetSubscriptionAttributesInput:
							in.SubscriptionArn = aws.String(subscriptions[aws.ToString(in.SubscriptionArn)])
						}
					})
					if row.Result.Code != "Success" {
						return
					}
					switch out := out.(type) {
					case *sns.CreateTopicOutput:
						var native sns.CreateTopicOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						if aws.ToString(out.TopicArn) != aws.ToString(native.TopicArn) {
							t.Fatal("topic source identity changed")
						}
					case *sqs.CreateQueueOutput:
						var native sqs.CreateQueueOutput
						var in sqs.CreateQueueInput
						awsDecodeJSON(t, row.Result.Output, &native)
						awsDecodeJSON(t, row.Input, &in)
						key := aws.ToString(native.QueueUrl)
						urls[key] = aws.ToString(out.QueueUrl)
						identities[key] = queueIdentity{row.Region, aws.ToString(in.QueueName)}
						// No same-name resources exist in these independent local scopes.
						wrongRegion := fixture.SourceRegion
						if wrongRegion == row.Region {
							wrongRegion = "us-west-2"
						}
						for _, wrong := range []*sqs.Client{queues(wrongRegion, fixture.Account), queues("us-east-1", "111111111111")} {
							out, err := wrong.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: in.QueueName})
							if err == nil || out != nil {
								t.Fatal("regional destination leaked into another account or Region")
							}
						}
					case *sqs.GetQueueAttributesOutput:
						var native sqs.GetQueueAttributesOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						for _, key := range []string{"QueueArn"} {
							if want, exists := native.Attributes[key]; exists {
								snsRegionalSQSAttribute(t, key, out.Attributes[key], want)
							}
						}
					case *sns.SubscribeOutput:
						var native sns.SubscribeOutput
						var in sns.SubscribeInput
						awsDecodeJSON(t, row.Result.Output, &native)
						awsDecodeJSON(t, row.Input, &in)
						prefix := aws.ToString(in.TopicArn) + ":"
						if !strings.HasPrefix(aws.ToString(out.SubscriptionArn), prefix) {
							t.Fatal("subscription moved out of source topic scope")
						}
						if _, err := uuid.Parse(strings.TrimPrefix(aws.ToString(out.SubscriptionArn), prefix)); err != nil {
							t.Fatal(err)
						}
						subscriptions[aws.ToString(native.SubscriptionArn)] = aws.ToString(out.SubscriptionArn)
					case *sns.GetSubscriptionAttributesOutput:
						var native sns.GetSubscriptionAttributesOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						for _, key := range []string{"TopicArn", "Endpoint", "Protocol", "Owner", "RawMessageDelivery", "RedrivePolicy", "FilterPolicy"} {
							if want, exists := native.Attributes[key]; exists {
								snsRegionalSQSAttribute(t, key, out.Attributes[key], want)
							}
						}
					case *sns.PublishOutput:
						var native sns.PublishOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						id := aws.ToString(out.MessageId)
						if _, err := uuid.Parse(id); err != nil {
							t.Fatal(err)
						}
						ids[id], published[id] = aws.ToString(native.MessageId), source.Now()
						sequences[id] = aws.ToString(out.SequenceNumber)
						if native.SequenceNumber != nil {
							if n, ok := new(big.Int).SetString(sequences[id], 10); !ok || n.Sign() <= 0 {
								t.Fatal("FIFO publish has no valid sequence number")
							}
						}
					}
				}) {
					t.FailNow()
				}
				if row.Label == "publish-fifo-original" {
					// Accepted FIFO publication and its destinations survive storage
					// reopen without a replacement publication or worker-specific API.
					reopenCloud()
				}
			}
			compareWindow()
		})
	}
}

func snsRegionalSQSAttribute(t *testing.T, key, actual, native string) {
	t.Helper()
	if key == "RedrivePolicy" || key == "FilterPolicy" {
		var got, want any
		awsDecodeJSON(t, []byte(actual), &got)
		awsDecodeJSON(t, []byte(native), &want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s differs: got %s, native %s", key, actual, native)
		}
		return
	}
	if actual != native {
		t.Fatalf("%s differs: got %q, native %q", key, actual, native)
	}
}
