package stackd_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

type eventTraceObservation struct {
	Case            string                           `json:"case"`
	Request         eventtypes.PutEventsRequestEntry `json:"request"`
	HTTPTraceHeader *string                          `json:"http_trace_header"`
	Trace           string                           `json:"trace"`
	GeneratedRoot   bool                             `json:"generated_root"`
	ErrorCode       string                           `json:"error_code"`
	EntryError      string                           `json:"entry_error"`
}

func eventTracePut(t *testing.T, clients cloudClients, row eventTraceObservation) (*eventbridge.PutEventsOutput, error) {
	t.Helper()
	entry := row.Request
	entry.EventBusName = aws.String(eventDeliveryName)
	if aws.ToString(entry.Source) == "stackd.trace" {
		entry.Source = aws.String(eventDeliveryName)
	}
	return eventDeliveryClient(clients, eventDeliveryAccount).PutEvents(t.Context(), &eventbridge.PutEventsInput{Entries: []eventtypes.PutEventsRequestEntry{entry}}, func(options *eventbridge.Options) {
		if row.HTTPTraceHeader != nil {
			options.APIOptions = append(options.APIOptions, func(stack *middleware.Stack) error {
				return stack.Build.Add(middleware.BuildMiddlewareFunc("EventTraceHeader", func(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
					in.Request.(*smithyhttp.Request).Header.Set("X-Amzn-Trace-Id", *row.HTTPTraceHeader)
					return next.HandleBuild(ctx, in)
				}), middleware.After)
			})
		}
	})
}

func eventTraceReceive(t *testing.T, cloud *stackd.Stack, clients cloudClients, url *string) []sqstypes.Message {
	t.Helper()
	if result, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || result.More {
		t.Fatalf("trace delivery did not settle: %+v %v", result, err)
	}
	queues := clients.sqs(eventDeliveryAccount, "test", "")
	var result []sqstypes.Message
	for {
		out, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: url, MaxNumberOfMessages: 10,
			MessageSystemAttributeNames: []sqstypes.MessageSystemAttributeName{sqstypes.MessageSystemAttributeNameAll}, MessageAttributeNames: []string{"All"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Messages) == 0 {
			return result
		}
		for _, message := range out.Messages {
			result = append(result, message)
			if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: url, ReceiptHandle: message.ReceiptHandle}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func eventTraceAssert(t *testing.T, row eventTraceObservation, message sqstypes.Message, id string) string {
	t.Helper()
	trace := message.Attributes["AWSTraceHeader"]
	want := row.Trace
	if row.GeneratedRoot {
		root := strings.SplitN(trace, ";", 2)[0]
		if !regexp.MustCompile(`^Root=1-[0-9a-f]{8}-[0-9a-f]{24}$`).MatchString(root) {
			t.Fatalf("missing generated root: %q", trace)
		}
		trace = strings.Replace(trace, root, "Root=<generated>", 1)
	}
	if trace != want {
		t.Fatalf("%s trace=%q native=%q", row.Case, trace, want)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 9 || string(body["id"]) != `"`+id+`"` {
		t.Fatalf("trace changed customer envelope: %s", aws.ToString(message.Body))
	}
	var detail, original any
	if err := json.Unmarshal(body["detail"], &detail); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(aws.ToString(row.Request.Detail)), &original); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(detail)
	wantDetail, _ := json.Marshal(original)
	if string(got) != string(wantDetail) {
		t.Fatalf("trace changed detail: %s", got)
	}
	if _, exists := message.MessageAttributes["AWSTraceHeader"]; exists {
		t.Fatal("trace became a customer message attribute")
	}
	return message.Attributes["AWSTraceHeader"]
}

func TestEventBridgeTraceNativeSDK(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/eventbridge/trace.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []eventTraceObservation `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			backends := storage.NewMemory()
			if kind == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "trace.sqlite"))
			}
			cloud, clients, _ := startEventDeliveryCloud(t, backends, clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)))
			urls := provisionEventDelivery(t, clients)
			setEventDeliveryPolicy(t, clients.sqs(eventDeliveryAccount, "test", ""), urls["target"], "target", nil)
			out, err := eventDeliveryClient(clients, eventDeliveryAccount).PutTargets(t.Context(), &eventbridge.PutTargetsInput{
				Rule: aws.String(eventDeliveryName), EventBusName: aws.String(eventDeliveryName), Targets: []eventtypes.Target{{
					Id: aws.String("missing"), Arn: aws.String(eventDeliveryQueueARN("absent")),
					DeadLetterConfig: &eventtypes.DeadLetterConfig{Arn: aws.String(eventDeliveryQueueARN("dlq"))},
					RetryPolicy:      &eventtypes.RetryPolicy{MaximumRetryAttempts: aws.Int32(0)},
				}}})
			if err != nil || out.FailedEntryCount != 0 {
				t.Fatal(out, err)
			}
			for _, row := range fixture.Observations {
				t.Run(row.Case, func(t *testing.T) {
					out, err := eventTracePut(t, clients, row)
					if row.ErrorCode != "" {
						assertAPIError(t, err, row.ErrorCode)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if row.EntryError != "" {
						if out.FailedEntryCount != 1 || aws.ToString(out.Entries[0].ErrorCode) != row.EntryError {
							t.Fatal(out)
						}
						return
					}
					if out.FailedEntryCount != 0 || len(out.Entries) != 1 {
						t.Fatal(out)
					}
					var retained string
					for _, sink := range []string{"target", "dlq"} {
						messages := eventTraceReceive(t, cloud, clients, urls[sink])
						if len(messages) != 1 {
							t.Fatalf("%s deliveries=%+v", sink, messages)
						}
						trace := eventTraceAssert(t, row, messages[0], aws.ToString(out.Entries[0].EventId))
						if sink == "target" {
							retained = trace
						} else if retained != trace {
							t.Fatalf("fanout regenerated trace: %q != %q", retained, trace)
						}
					}
				})
			}
		})
	}
}

func TestEventBridgeTraceRetainedDeliveryAndReplaySQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.sqlite")
	backends, closeDB := openSQLiteBackends(t, path)
	gate := &gatedQueueRepository{Repository: backends.SQS, entered: make(chan struct{}), release: make(chan struct{})}
	backends.SQS = gate
	t.Cleanup(gate.unblock)
	source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
	_, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
	urls := provisionEventDelivery(t, clients)
	setEventDeliveryPolicy(t, clients.sqs(eventDeliveryAccount, "test", ""), urls["target"], "target", nil)
	trace := "Root=1-6ab2832c-0123456789abcdef01234567;Parent=0123456789abcdef;Sampled=0"
	row := eventTraceObservation{Case: "reopen", Trace: trace, Request: eventtypes.PutEventsRequestEntry{
		Source: aws.String("stackd.trace"), DetailType: aws.String("trace"), Detail: aws.String(`{"private":"retained"}`), TraceHeader: &trace}}
	archive, err := eventDeliveryClient(clients, eventDeliveryAccount).CreateArchive(t.Context(), &eventbridge.CreateArchiveInput{
		ArchiveName: aws.String("trace"), EventSourceArn: aws.String(eventDeliveryBusARN),
	})
	if err != nil {
		t.Fatal(err)
	}
	gate.armed.Store(true)
	out, err := eventTracePut(t, clients, row)
	if err != nil || out.FailedEntryCount != 0 {
		t.Fatal(out, err)
	}
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("target command did not reach the persistence boundary")
	}
	closeCloud()
	closeDB()
	backends, _ = openSQLiteBackends(t, path)
	cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
	queue, err := clients.sqs(eventDeliveryAccount, "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String(eventDeliveryName + "-target")})
	if err != nil {
		t.Fatal(err)
	}
	messages := eventTraceReceive(t, cloud, clients, queue.QueueUrl)
	if len(messages) != 1 {
		t.Fatalf("reopened deliveries: %+v", messages)
	}
	eventTraceAssert(t, row, messages[0], aws.ToString(out.Entries[0].EventId))
	// Replaying stored customer JSON must not resurrect the original transport
	// metadata, even though ordinary retry/reopen above must preserve it.
	replay, err := eventDeliveryClient(clients, eventDeliveryAccount).StartReplay(t.Context(), &eventbridge.StartReplayInput{
		ReplayName: aws.String("trace-replay"), EventSourceArn: archive.ArchiveArn,
		EventStartTime: aws.Time(source.Now().Add(-time.Second)), EventEndTime: aws.Time(source.Now().Add(time.Second)),
		Destination: &eventtypes.ReplayDestination{Arn: aws.String(eventDeliveryBusARN)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if replay.State != "STARTING" {
		t.Fatalf("replay admission: %+v", replay)
	}
	if err := source.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	replayed := eventTraceReceive(t, cloud, clients, queue.QueueUrl)
	if len(replayed) != 1 {
		t.Fatalf("replay deliveries: %+v", replayed)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(aws.ToString(replayed[0].Body)), &body); err != nil {
		t.Fatal(err)
	}
	if replayed[0].Attributes["AWSTraceHeader"] != "" || len(body) != 10 || string(body["replay-name"]) != `"trace-replay"` ||
		string(body["detail"]) != `{"private":"retained"}` || string(body["id"]) == `"`+aws.ToString(out.Entries[0].EventId)+`"` {
		t.Fatalf("replay resurrected trace or changed detail: %+v", replayed[0])
	}
}
