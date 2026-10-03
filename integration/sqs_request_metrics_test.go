package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type sqsRequestMetricOperation struct {
	Label, Operation string
	Inputs           json.RawMessage
	Output           struct {
		QueueURL   string `json:"QueueUrl"`
		MessageID  string `json:"MessageId"`
		Messages   []struct{ MessageId, ReceiptHandle, Body string }
		Successful []sqstypes.SendMessageBatchResultEntry
		Failed     []sqstypes.BatchResultErrorEntry
	}
	Error struct{ Error struct{ Code string } }
}

func TestSQSNativeRequestMetricDistributions(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/sqs/request_metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Evidence []struct {
			Operations []sqsRequestMetricOperation
			Metrics    []struct {
				Input  cloudwatch.GetMetricStatisticsInput
				Output cloudwatch.GetMetricStatisticsOutput
			}
		}
		Replays []struct {
			Name       string
			Evidence   int
			Bucket     time.Time
			Operations []string
			Metrics    []string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, replay := range fixture.Replays {
			t.Run(backend+"/"+replay.Name, func(t *testing.T) {
				evidence := fixture.Evidence[replay.Evidence]
				path := filepath.Join(t.TempDir(), "request-metrics.sqlite")
				backends := storage.NewMemory()
				closeDatabase := func() {}
				if backend == "sqlite" {
					backends, closeDatabase = openSQLiteBackends(t, path)
				}
				// Fresh local queues isolate request contributions. The native later
				// idle zeros remain in the fixture, not an exact scheduling assertion.
				source := clock.NewManual(replay.Bucket.Add(time.Second))
				pollClock := &sqsReceiveDeadlineClock{Manual: source, deadline: source.Now().Add(20 * time.Second), registered: make(chan struct{})}
				_, c, closeCloud := startEventDeliveryCloud(t, backends, pollClock)
				client := c.sqs("test", "test", "")
				var replacements, urls []string
				identities := make(map[string]string)
				bindIdentity := func(native string, actual *string) {
					t.Helper()
					if previous, exists := identities[native]; exists && previous != aws.ToString(actual) {
						t.Fatalf("accepted duplicate changed message identity: %s != %s", previous, aws.ToString(actual))
					}
					for other, previous := range identities {
						if other != native && previous == aws.ToString(actual) {
							t.Fatal("distinct native messages were incorrectly deduplicated")
						}
					}
					identities[native] = aws.ToString(actual)
				}
				for _, label := range replay.Operations {
					index := slices.IndexFunc(evidence.Operations, func(row sqsRequestMetricOperation) bool { return row.Label == label })
					if index < 0 {
						t.Fatalf("missing retained operation %s", label)
					}
					row := evidence.Operations[index]
					input := sqsRequestMetricInput(t, row.Inputs)
					input = json.RawMessage(strings.NewReplacer(replacements...).Replace(string(input)))
					parts := strings.Split(row.Operation, "_")
					for i, part := range parts {
						parts[i] = strings.ToUpper(part[:1]) + part[1:]
					}
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					type response struct {
						output any
						err    error
					}
					call := func() response {
						out, err := awstest.CallSDK(ctx, client, strings.Join(parts, ""), input, func(in any) {
							if in, ok := in.(*sqs.ReceiveMessageInput); ok {
								// Match observed standard partition batch sizes, not order.
								// FIFO and rejected queues retain the full requested maximum.
								if len(row.Output.Messages) > 0 && !strings.HasSuffix(aws.ToString(in.QueueUrl), ".fifo") {
									in.MaxNumberOfMessages = int32(len(row.Output.Messages))
								}
								if len(row.Output.Messages) == 0 && in.WaitTimeSeconds != 20 {
									in.WaitTimeSeconds = 0
								}
							}
						})
						return response{out, err}
					}
					var in struct{ WaitTimeSeconds int32 }
					if err := json.Unmarshal(input, &in); err != nil {
						t.Fatal(err)
					}
					var result response
					if row.Operation == "receive_message" && in.WaitTimeSeconds == 20 {
						done := make(chan response, 1)
						go func() { done <- call() }()
						pollClock.wait(t, ctx)
						advanceClock(t, source, 20*time.Second)
						select {
						case result = <-done:
						case <-ctx.Done():
							t.Fatalf("%s did not complete at its modeled deadline", label)
						}
					} else {
						result = call()
					}
					cancel()
					if code := row.Error.Error.Code; code != "" {
						sqsRequestMetricError(t, label, result.err, code)
						continue
					}
					if result.err != nil {
						t.Fatalf("%s: %v", label, result.err)
					}
					switch out := result.output.(type) {
					case *sqs.CreateQueueOutput:
						replacements = append(replacements, row.Output.QueueURL, aws.ToString(out.QueueUrl))
						urls = append(urls, aws.ToString(out.QueueUrl))
					case *sqs.SendMessageOutput:
						bindIdentity(row.Output.MessageID, out.MessageId)
					case *sqs.SendMessageBatchOutput:
						if len(out.Successful) != len(row.Output.Successful) {
							t.Fatalf("%s: accepted entries %+v, native %+v", label, out.Successful, row.Output.Successful)
						}
						for _, native := range row.Output.Successful {
							i := slices.IndexFunc(out.Successful, func(entry sqstypes.SendMessageBatchResultEntry) bool {
								return aws.ToString(entry.Id) == aws.ToString(native.Id)
							})
							if i < 0 {
								t.Fatalf("%s: missing accepted entry %s", label, aws.ToString(native.Id))
							}
							bindIdentity(aws.ToString(native.MessageId), out.Successful[i].MessageId)
						}
						sqsRequestMetricFailures(t, label, out.Failed, row.Output.Failed)
					case *sqs.DeleteMessageBatchOutput:
						if len(out.Successful) != len(row.Output.Successful) {
							t.Fatalf("%s: accepted deletes %+v, native %+v", label, out.Successful, row.Output.Successful)
						}
						sqsRequestMetricFailures(t, label, out.Failed, row.Output.Failed)
					case *sqs.ReceiveMessageOutput:
						if len(out.Messages) != len(row.Output.Messages) {
							t.Fatalf("%s: received %d messages, native %d", label, len(out.Messages), len(row.Output.Messages))
						}
						for i, message := range out.Messages {
							// These actual receipts, never native handles, feed later deletes.
							replacements = append(replacements, row.Output.Messages[i].ReceiptHandle, aws.ToString(message.ReceiptHandle))
						}
					}
				}
				// Reconstruct the service and retained stores before publication;
				// then delete the queues without discarding their pending samples.
				closeCloud()
				closeDatabase()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, path)
				}
				cloud, c, _ := startEventDeliveryCloud(t, backends, source)
				client = c.sqs("test", "test", "")
				for _, url := range urls {
					if _, err := client.DeleteQueue(t.Context(), &sqs.DeleteQueueInput{QueueUrl: &url}); err != nil {
						t.Fatal(err)
					}
				}
				end := replay.Bucket.Add(time.Minute)
				advanceClock(t, source, end.Sub(source.Now()))
				trailNativeDrain(t, cloud)
				metrics := metricsClient(c, "test")
				for _, native := range evidence.Metrics {
					if len(replay.Metrics) > 0 && !slices.Contains(replay.Metrics, aws.ToString(native.Input.MetricName)) {
						continue
					}
					query := native.Input
					query.StartTime, query.EndTime = &replay.Bucket, &end
					out, err := metrics.GetMetricStatistics(t.Context(), &query)
					if err != nil {
						t.Fatal(err)
					}
					var want []cwtypes.Datapoint
					for _, point := range native.Output.Datapoints {
						if point.Timestamp.Equal(replay.Bucket) {
							want = append(want, point)
						}
					}
					if len(out.Datapoints) != len(want) {
						t.Fatalf("%s/%s: got %+v, native request bucket %+v (missing is not zero)", aws.ToString(query.Dimensions[0].Value), aws.ToString(query.MetricName), out.Datapoints, want)
					}
					for i, got := range out.Datapoints {
						values := func(p cwtypes.Datapoint) [5]*float64 {
							return [5]*float64{p.Sum, p.SampleCount, p.Minimum, p.Maximum, p.Average}
						}
						if !reflect.DeepEqual(values(got), values(want[i])) || got.Unit != want[i].Unit || !got.Timestamp.Equal(*want[i].Timestamp) {
							t.Fatalf("%s/%s: got %+v, native %+v", aws.ToString(query.Dimensions[0].Value), aws.ToString(query.MetricName), got, want[i])
						}
					}
				}
			})
		}
	}
}

// Native bytes retain an explicit base64 envelope. Go's SDK JSON decoder takes
// the same base64 payload as a string and supplies decoded bytes to SendMessage.
func sqsRequestMetricInput(t *testing.T, raw json.RawMessage) json.RawMessage {
	t.Helper()
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	messages := []any{input}
	if entries, ok := input["Entries"].([]any); ok {
		messages = append(messages, entries...)
	}
	for _, message := range messages {
		attributes, _ := message.(map[string]any)["MessageAttributes"].(map[string]any)
		for _, value := range attributes {
			attribute := value.(map[string]any)
			if binary, ok := attribute["BinaryValue"].(map[string]any); ok {
				if binary["encoding"] != "base64" {
					t.Fatalf("unsupported native binary encoding: %v", binary)
				}
				attribute["BinaryValue"] = binary["data"]
			}
		}
	}
	inputJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return inputJSON
}

func sqsRequestMetricError(t *testing.T, label string, err error, native string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != native {
		t.Fatalf("%s: got %v, native error code %s", label, err, native)
	}
	// SQS models these preflight errors explicitly; missing/invalid parameters
	// are generic API errors in the SDK model. Never pin native error wording.
	var target any
	switch strings.TrimPrefix(native, "AWS.SimpleQueueService.") {
	case "BatchEntryIdsNotDistinct":
		target = new(*sqstypes.BatchEntryIdsNotDistinct)
	case "InvalidBatchEntryId":
		target = new(*sqstypes.InvalidBatchEntryId)
	case "TooManyEntriesInBatchRequest":
		target = new(*sqstypes.TooManyEntriesInBatchRequest)
	default:
		target = new(*smithy.GenericAPIError)
	}
	if !errors.As(err, target) {
		t.Fatalf("%s: expected SDK error %T, got %v", label, target, err)
	}
}

func sqsRequestMetricFailures(t *testing.T, label string, got, want []sqstypes.BatchResultErrorEntry) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: failed entries %+v, native %+v", label, got, want)
	}
	for _, native := range want {
		i := slices.IndexFunc(got, func(entry sqstypes.BatchResultErrorEntry) bool {
			return aws.ToString(entry.Id) == aws.ToString(native.Id)
		})
		if i < 0 || aws.ToString(got[i].Code) != aws.ToString(native.Code) || got[i].SenderFault != native.SenderFault {
			t.Fatalf("%s: failed entries %+v, native %+v", label, got, want)
		}
	}
}
