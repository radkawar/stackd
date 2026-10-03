package stackd_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
)

type subscriptionLogEvent struct {
	ID              string            `json:"id"`
	Timestamp       int64             `json:"timestamp"`
	Message         string            `json:"message"`
	ExtractedFields map[string]string `json:"extractedFields,omitempty"`
}

type subscriptionEnvelope struct {
	MessageType, Owner, LogGroup, LogStream string
	SubscriptionFilters                     []string
	LogEvents                               []subscriptionLogEvent
}

type subscriptionRecord struct {
	Envelope           subscriptionEnvelope `json:"envelope"`
	HandlerRequestID   string               `json:"handler_request_id"`
	InvokedFunctionARN string               `json:"invoked_function_arn"`
}

type subscriptionFixture struct {
	Observations []eventLogsObservation
	Deliveries   []struct{ Record subscriptionRecord }
}

func loadSubscriptionFixture(t *testing.T) subscriptionFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/logs/subscriptions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture subscriptionFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

type subscriptionEventKey struct {
	Filter, Stream, Message string
	Timestamp               int64
}

func subscriptionKey(filter, stream string, event subscriptionLogEvent) subscriptionEventKey {
	return subscriptionEventKey{filter, stream, event.Message, event.Timestamp}
}

// Native delivery grouping and timing are not deterministic. Compare each
// observed event's envelope, bytes, system fields and source-ID relationships.
func subscriptionExpected(f subscriptionFixture, input *cloudwatchlogs.PutLogEventsInput) map[subscriptionEventKey]subscriptionLogEvent {
	wanted := make(map[subscriptionEventKey]subscriptionLogEvent)
	for _, delivery := range f.Deliveries {
		e := delivery.Record.Envelope
		if e.LogGroup != aws.ToString(input.LogGroupName) || e.LogStream != aws.ToString(input.LogStreamName) {
			continue
		}
		for _, event := range e.LogEvents {
			for _, inputEvent := range input.LogEvents {
				if event.Timestamp == aws.ToInt64(inputEvent.Timestamp) && event.Message == aws.ToString(inputEvent.Message) {
					for _, filter := range e.SubscriptionFilters {
						wanted[subscriptionKey(filter, e.LogStream, event)] = event
					}
				}
			}
		}
	}
	return wanted
}

func subscriptionReceive(t *testing.T, c *lambdaEventsCloud, logs *cloudwatchlogs.Client, group string, wanted map[subscriptionEventKey]subscriptionLogEvent, received map[subscriptionEventKey]subscriptionLogEvent, requests map[string]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for {
		if _, err := c.cloud.RunDueJobs(ctx, 100); err != nil {
			t.Fatal(err)
		}
		out, err := c.queues.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: c.outputURL, MaxNumberOfMessages: 10})
		if err != nil {
			t.Fatal(err)
		}
		for _, message := range out.Messages {
			var record subscriptionRecord
			if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &record); err != nil {
				t.Fatal(err)
			}
			e := record.Envelope
			if e.MessageType != "DATA_MESSAGE" || e.Owner != "000000000000" || e.LogGroup != group || len(e.SubscriptionFilters) != 1 || record.InvokedFunctionARN != c.functionARN {
				t.Fatalf("unexpected real Lambda subscription envelope: %+v", record)
			}
			stored, err := logs.FilterLogEvents(ctx, &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String(group), LogStreamNames: []string{e.LogStream}})
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range e.LogEvents {
				found := false
				for _, original := range stored.Events {
					if aws.ToString(original.EventId) == event.ID && aws.ToString(original.Message) == event.Message && aws.ToInt64(original.Timestamp) == event.Timestamp {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("subscription event is not the accepted source log record: %+v", event)
				}
				key := subscriptionKey(e.SubscriptionFilters[0], e.LogStream, event)
				if prior, ok := received[key]; ok && !reflect.DeepEqual(prior, event) {
					t.Fatalf("redelivery changed an accepted event: %+v -> %+v", prior, event)
				}
				received[key] = event
			}
			requests[aws.ToString(message.MessageId)] = record.HandlerRequestID
			if _, err := c.queues.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: c.outputURL, ReceiptHandle: message.ReceiptHandle}); err != nil {
				t.Fatal(err)
			}
		}
		complete := true
		for key, native := range wanted {
			got, ok := received[key]
			if !ok {
				complete = false
				continue
			}
			// IDs are opaque; equality with FilterLogEvents was checked above.
			native.ID = got.ID
			if !reflect.DeepEqual(got, native) {
				t.Fatalf("subscription payload differs from native: got %+v, native %+v", got, native)
			}
		}
		if complete {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for native subscription effects: %v; wanted %+v", ctx.Err(), wanted)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestLogsSubscriptionsNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real Logs subscription delivery")
	}
	fixture := loadSubscriptionFixture(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "subscriptions.sqlite"))
			}
			source := clock.NewManual(time.UnixMilli(fixture.Observations[0].Started).UTC())
			c := lambdaEventsConnect(t, backends, source)
			root := (cloudClients{c.server}).iam("test", "test", "")
			logs := logsClient(cloudClients{c.server}, "test")
			clients := map[string]any{"logs": logs, "iam": root, "lambda": c.lambda, "sqs": c.queues}
			tokens := make(map[string]string)
			created := make(map[int64]int64)
			received := make(map[subscriptionEventKey]subscriptionLogEvent)
			requests := make(map[string]string)
			group := ""
			for _, row := range fixture.Observations {
				if strings.HasPrefix(row.Label, "cleanup-") {
					break
				}
				// CLI validation and native polling/propagation are capture evidence,
				// not successful API commands or deterministic local timing contracts.
				if clients[row.Service] == nil || row.Result.Code == "CLIError" || row.Service == "sqs" && row.Operation != "create-queue" || row.Service == "lambda" && (row.Operation == "get-function-configuration" || row.Operation == "get-function" || row.Operation == "create-function" && row.Result.Code != "Success") {
					continue
				}
				t.Run(row.Label, func(t *testing.T) {
					if at := time.UnixMilli(row.Started); at.After(source.Now()) {
						advanceClock(t, source, at.Sub(source.Now()))
					}
					out := replayEventLogs(t, clients[row.Service], row, func(value any) {
						switch input := value.(type) {
						case *awslambda.CreateFunctionInput:
							input.Environment.Variables["QUEUE_URL"] = strings.Replace(aws.ToString(c.outputURL), "127.0.0.1", "host.docker.internal", 1)
							c.functionName = input.FunctionName
						case *cloudwatchlogs.DescribeSubscriptionFiltersInput:
							if token, ok := tokens[aws.ToString(input.NextToken)]; ok {
								input.NextToken = aws.String(token)
							}
						}
					})
					if out == nil {
						return
					}
					switch out := out.(type) {
					case *sqs.CreateQueueOutput:
						c.outputURL = out.QueueUrl
					case *awslambda.CreateFunctionOutput:
						c.functionARN = aws.ToString(out.FunctionArn)
						if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: c.functionName}, time.Minute); err != nil {
							t.Fatal(err)
						}
					case *cloudwatchlogs.CreateLogGroupOutput:
						var input cloudwatchlogs.CreateLogGroupInput
						if err := json.Unmarshal(row.Input, &input); err != nil {
							t.Fatal(err)
						}
						group = aws.ToString(input.LogGroupName)
					case *cloudwatchlogs.DescribeSubscriptionFiltersOutput:
						var native cloudwatchlogs.DescribeSubscriptionFiltersOutput
						if err := json.Unmarshal(row.Result.Output, &native); err != nil {
							t.Fatal(err)
						}
						if len(out.SubscriptionFilters) != len(native.SubscriptionFilters) || (out.NextToken == nil) != (native.NextToken == nil) {
							t.Fatalf("subscription page differs: got %+v, native %+v", out, native)
						}
						if native.NextToken != nil {
							tokens[*native.NextToken] = aws.ToString(out.NextToken)
						}
						for i, want := range native.SubscriptionFilters {
							got := out.SubscriptionFilters[i]
							if (got.CreationTime == nil) != (want.CreationTime == nil) {
								t.Fatal("creation time presence differs")
							}
							if prior, ok := created[aws.ToInt64(want.CreationTime)]; ok && prior != aws.ToInt64(got.CreationTime) {
								t.Fatal("replacement changed the original creation time")
							}
							created[aws.ToInt64(want.CreationTime)] = aws.ToInt64(got.CreationTime)
							got.CreationTime = want.CreationTime
							if !reflect.DeepEqual(got, want) {
								t.Fatalf("stored subscription differs: got %+v, native %+v", got, want)
							}
						}
					case *cloudwatchlogs.PutLogEventsOutput:
						var input cloudwatchlogs.PutLogEventsInput
						var native cloudwatchlogs.PutLogEventsOutput
						if err := json.Unmarshal(row.Input, &input); err != nil {
							t.Fatal(err)
						}
						if err := json.Unmarshal(row.Result.Output, &native); err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(out.RejectedLogEventsInfo, native.RejectedLogEventsInfo) {
							t.Fatalf("partial admission differs: got %+v, native %+v", out.RejectedLogEventsInfo, native.RejectedLogEventsInfo)
						}
						subscriptionReceive(t, c, logs, group, subscriptionExpected(fixture, &input), received, requests)
					}
				})
				if t.Failed() {
					return // Later native observations depend on this accepted state.
				}
			}
			assertSubscriptionCausality(t, backends.Journal, c.functionARN, group, requests)
		})
	}
}

func assertSubscriptionCausality(t *testing.T, events journal.Storage, functionARN, group string, requests map[string]string) {
	t.Helper()
	rows, err := events.Read(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	batches := make(map[string]journal.Event)
	invocations := make(map[string]journal.Event)
	for _, event := range rows {
		if event.LogsBatchAccepted.BatchID != "" {
			batches[event.LogsBatchAccepted.BatchID] = event
		}
		if event.LambdaInvocationAccepted.FunctionARN == functionARN {
			invocations[event.LambdaInvocationAccepted.InvocationID] = event
		}
	}
	for _, invocation := range invocations {
		batch, ok := batches[invocation.ParentEventID]
		if !ok || batch.LogsBatchAccepted.LogGroupARN != "arn:aws:logs:us-east-1:000000000000:log-group:"+group || batch.RequestID == "" || batch.Sequence >= invocation.Sequence {
			t.Fatalf("Lambda acceptance lost its committed source batch: %+v, %+v", invocation, batch)
		}
	}
	linked := 0
	for _, event := range rows {
		if request, observed := requests[event.SQSMessageAccepted.MessageID]; observed {
			invocation, ok := invocations[event.ParentEventID]
			if !ok || invocation.Sequence >= event.Sequence || invocation.RequestID != request {
				t.Fatalf("runtime SDK call inherited another invocation's origin: %+v, handler request %q", event, request)
			}
			linked++
		}
	}
	if linked == 0 || linked != len(requests) {
		t.Fatalf("committed Logs -> Lambda -> SQS paths: %d, observed runtime effects %d", linked, len(requests))
	}
}
