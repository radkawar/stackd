package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"stackd/clock"
	"stackd/internal/scheduler"
	snsstore "stackd/storage/sns"
)

// Replay the captured acceptance decisions and consumer-visible payloads. IDs
// are correlated across retries rather than compared with native random values.
func TestSNSNativeFIFO(t *testing.T) {
	for _, name := range []string{"fifo", "fifo_edges", "fifo_projection", "fifo_redrive"} {
		data, err := os.ReadFile("../testdata/aws/sns/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var fixture snsAdmissionFixture
		awsDecodeJSON(t, data, &fixture)
		// Local service time is deterministic; native fixtures do not invent request times.
		fixture.Observations[0].Started = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(name+"/"+backend, func(t *testing.T) {
				cloud, clients, source := admissionFixtureCloud(t, backend, fixture)
				topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
				queues := clients.sqs(fixture.Account, "test", "")
				urls := map[string]string{}
				subscriptions := map[string]string{}
				ids, sequences, reverse := map[string]string{}, map[string]string{}, map[string]string{}
				wanted, received := map[string][]sqstypes.Message{}, map[string][]sqstypes.Message{}
				correlate := func(nativeID, nativeSequence, localID, localSequence string) {
					t.Helper()
					if previous, ok := ids[nativeID]; ok && (previous != localID || sequences[nativeID] != localSequence) {
						t.Fatalf("duplicate changed accepted identity: %s/%s -> %s/%s", previous, sequences[nativeID], localID, localSequence)
					}
					if prior, ok := reverse[localID]; ok && prior != nativeID {
						t.Fatalf("distinct native publications collapsed: %s and %s", prior, nativeID)
					}
					if nativeSequence != "" && localSequence == "" {
						t.Fatal("FIFO publication omitted sequence")
					}
					ids[nativeID], sequences[nativeID], reverse[localID] = localID, localSequence, nativeID
				}
				for _, row := range fixture.Observations {
					if strings.HasPrefix(row.Label, "cleanup-") || row.Label == "before-recreate" {
						break
					}
					if row.Service == "sts" || row.Operation == "delete-message" {
						continue
					}
					if row.Label == "expiry" {
						advanceClock(t, source, 310*time.Second)
					}
					if row.Operation == "receive-message" {
						var input sqs.ReceiveMessageInput
						var native sqs.ReceiveMessageOutput
						awsDecodeJSON(t, row.Input, &input)
						awsDecodeJSON(t, row.Result.Output, &native)
						key := aws.ToString(input.QueueUrl)
						wanted[key] = append(wanted[key], native.Messages...)
						received[key] = append(received[key], snsAdmissionReceive(t, cloud, queues, aws.String(urls[key]))...)
						continue
					}
					prepare := func(input any) {
						switch in := input.(type) {
						case *sqs.GetQueueAttributesInput:
							in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
						case *sqs.SetQueueAttributesInput:
							in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
						case *sns.SetSubscriptionAttributesInput:
							in.SubscriptionArn = aws.String(subscriptions[aws.ToString(in.SubscriptionArn)])
						}
					}
					var client any = topics
					if row.Service == "sqs" {
						client = queues
					}
					output := snsControlReplay(t, client, row, prepare)
					if row.Result.Code != "Success" {
						continue
					}
					switch out := output.(type) {
					case *sqs.CreateQueueOutput:
						var native sqs.CreateQueueOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						urls[aws.ToString(native.QueueUrl)] = aws.ToString(out.QueueUrl)
					case *sns.SubscribeOutput:
						var native sns.SubscribeOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						subscriptions[aws.ToString(native.SubscriptionArn)] = aws.ToString(out.SubscriptionArn)
					case *sns.GetTopicAttributesOutput:
						var native sns.GetTopicAttributesOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						for _, key := range []string{"FifoTopic", "ContentBasedDeduplication", "FifoThroughputScope"} {
							if out.Attributes[key] != native.Attributes[key] {
								t.Fatalf("%s: %s got %q want %q", row.Label, key, out.Attributes[key], native.Attributes[key])
							}
						}
					case *sns.PublishOutput:
						var native sns.PublishOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						correlate(aws.ToString(native.MessageId), aws.ToString(native.SequenceNumber), aws.ToString(out.MessageId), aws.ToString(out.SequenceNumber))
						// Fix target acceptance order before the next publication. Queue-wide
						// SQS deduplication otherwise chooses whichever independent SNS group
						// happens to arrive first; FIFO does not order those groups.
						trailNativeDrain(t, cloud)
					case *sns.PublishBatchOutput:
						var native sns.PublishBatchOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						if len(out.Successful) != len(native.Successful) || len(out.Failed) != len(native.Failed) {
							t.Fatalf("%s: mixed batch outcomes differ: %+v", row.Label, out)
						}
						for i, entry := range out.Successful {
							expected := native.Successful[i]
							if aws.ToString(entry.Id) != aws.ToString(expected.Id) {
								t.Fatal("batch entry identity changed")
							}
							correlate(aws.ToString(expected.MessageId), aws.ToString(expected.SequenceNumber), aws.ToString(entry.MessageId), aws.ToString(entry.SequenceNumber))
						}
						trailNativeDrain(t, cloud)
					}
				}
				for queue, expected := range wanted {
					project := func(messages []sqstypes.Message, local bool) map[string][]string {
						groups := map[string][]string{}
						for _, message := range messages {
							body := aws.ToString(message.Body)
							var envelope map[string]any
							if json.Unmarshal([]byte(body), &envelope) == nil && envelope["Type"] == "Notification" {
								id := envelope["MessageId"].(string)
								if local {
									id = reverse[id]
									envelope["MessageId"] = id
								}
								if _, ok := envelope["SequenceNumber"]; ok {
									envelope["SequenceNumber"] = sequences[id]
								}
								delete(envelope, "Timestamp")
								delete(envelope, "UnsubscribeURL")
								encoded, err := json.Marshal(envelope)
								if err != nil {
									t.Fatal(err)
								}
								body = string(encoded)
							}
							payload := struct {
								Body, Group, Deduplication string
								Attributes                 map[string]sqstypes.MessageAttributeValue
							}{body, message.Attributes["MessageGroupId"], message.Attributes["MessageDeduplicationId"], message.MessageAttributes}
							encoded, err := json.Marshal(payload)
							if err != nil {
								t.Fatal(err)
							}
							groups[payload.Group] = append(groups[payload.Group], string(encoded))
						}
						// Standard SQS promises neither arrival nor receive order. FIFO groups do.
						if !strings.HasSuffix(queue, ".fifo") {
							for _, values := range groups {
								sort.Strings(values)
							}
						}
						return groups
					}
					got, want := project(received[queue], true), project(expected, false)
					if !reflect.DeepEqual(got, want) {
						t.Errorf("%s consumer deliveries differ\ngot: %v\nwant: %v", queue, got, want)
					}
				}
			})
		}
	}
}

// Hold automatic delivery discovery only on the first process. Public SNS
// admission and SQLite commits remain real; reopening installs the ordinary
// repository and must recover every accepted delivery without another publish.
type snsFIFOStoppedWorker struct{ snsstore.Repository }
type snsFIFOStoppedReader struct{ snsstore.Reader }

func (r snsFIFOStoppedWorker) View(ctx context.Context, fn func(snsstore.Reader) error) error {
	return r.Repository.View(ctx, func(reader snsstore.Reader) error { return fn(snsFIFOStoppedReader{reader}) })
}
func (r snsFIFOStoppedReader) NextDelivery() (scheduler.Job, bool, error) {
	return scheduler.Job{}, false, nil
}

func TestSQLiteSNSFIFORecoveryAndGroupProgress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sns-fifo.sqlite")
	backends, closeDatabase := openSQLiteBackends(t, path)
	source := clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	backends.SNS = snsFIFOStoppedWorker{backends.SNS}
	cloud, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
	const account = "000000000000"
	topics, queues := admissionSNSClient(clients, account, "us-east-1"), clients.sqs(account, "test", "")
	topic, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: aws.String("recovery.fifo"), Attributes: map[string]string{"FifoTopic": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	createQueue := func(name string) *string {
		t.Helper()
		queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: &name, Attributes: map[string]string{"FifoQueue": "true"}})
		if err != nil {
			t.Fatal(err)
		}
		arn := "arn:aws:sqs:us-east-1:" + account + ":" + name
		policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, arn, aws.ToString(topic.TopicArn))
		if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
			t.Fatal(err)
		}
		if _, err := topics.Subscribe(t.Context(), &sns.SubscribeInput{TopicArn: topic.TopicArn, Protocol: aws.String("sqs"), Endpoint: &arn, Attributes: map[string]string{"RawMessageDelivery": "true"}}); err != nil {
			t.Fatal(err)
		}
		return queue.QueueUrl
	}
	publish := func(body, group, dedup string) *sns.PublishOutput {
		t.Helper()
		out, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: topic.TopicArn, Message: &body, MessageGroupId: &group, MessageDeduplicationId: &dedup})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	firstQueue := createQueue("first.fifo")
	original := publish("first", "blocked", "first")
	// Model the retained due time of a retry before shutdown. No target effect
	// has happened; recovery must not select the younger same-group delivery.
	if err := backends.SNS.Update(t.Context(), func(tx snsstore.Transaction) error {
		job, found, err := tx.NextDelivery()
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("accepted publication has no pending delivery")
		}
		delivery, err := tx.Delivery(job.Key)
		if err != nil {
			return err
		}
		delivery.Due = source.Now().Add(time.Minute)
		delivery.Attempts, delivery.Version = 6, delivery.Version+1
		return tx.PutDelivery(delivery)
	}); err != nil {
		t.Fatal(err)
	}
	secondQueue := createQueue("second.fifo")
	publish("second", "blocked", "second")
	publish("independent", "free", "independent")
	closeCloud()
	closeDatabase()
	backends, _ = openSQLiteBackends(t, path)
	cloud, clients, _ = startEventDeliveryCloud(t, backends, source)
	topics, queues = admissionSNSClient(clients, account, "us-east-1"), clients.sqs(account, "test", "")
	for name, destination := range map[string]**string{"first.fifo": &firstQueue, "second.fifo": &secondQueue} {
		out, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: &name})
		if err != nil {
			t.Fatal(err)
		}
		*destination = out.QueueUrl
	}
	duplicate := publish("must-not-fanout", "other", "first")
	if aws.ToString(duplicate.MessageId) != aws.ToString(original.MessageId) || aws.ToString(duplicate.SequenceNumber) != aws.ToString(original.SequenceNumber) {
		t.Fatal("restart lost topic-wide deduplication")
	}
	bodies := func(url *string) []string {
		t.Helper()
		out := []string{}
		for _, message := range snsAdmissionReceive(t, cloud, queues, url) {
			out = append(out, aws.ToString(message.Body))
		}
		return out
	}
	if got := bodies(firstQueue); !reflect.DeepEqual(got, []string{"independent"}) {
		t.Fatalf("blocked group prevented independent delivery or overtook predecessor: %v", got)
	}
	got := bodies(secondQueue)
	sort.Strings(got)
	if !reflect.DeepEqual(got, []string{"independent", "second"}) {
		t.Fatalf("another subscription was blocked or received a duplicate: %v", got)
	}
	advanceClock(t, source, time.Minute)
	if got := bodies(firstQueue); !reflect.DeepEqual(got, []string{"first", "second"}) {
		t.Fatalf("recovered group order: %v", got)
	}
	advanceClock(t, source, 4*time.Minute-time.Nanosecond)
	if got := publish("still-duplicate", "blocked", "first"); aws.ToString(got.MessageId) != aws.ToString(original.MessageId) {
		t.Fatal("dedup expired before five minutes")
	}
	advanceClock(t, source, time.Nanosecond)
	renewed := publish("new-window", "blocked", "first")
	if aws.ToString(renewed.MessageId) == aws.ToString(original.MessageId) {
		t.Fatal("duplicate retry extended the original dedup window")
	}
	if _, err := topics.DeleteTopic(t.Context(), &sns.DeleteTopicInput{TopicArn: topic.TopicArn}); err != nil {
		t.Fatal(err)
	}
	recreated, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: aws.String("recovery.fifo"), Attributes: map[string]string{"FifoTopic": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	topic = recreated
	if got := publish("recreated", "blocked", "first"); aws.ToString(got.MessageId) == aws.ToString(renewed.MessageId) {
		t.Fatal("recreated topic inherited a receipt")
	}
}
