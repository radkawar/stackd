package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
	logstorage "stackd/storage/logs"
)

type subscriptionSourceFailure struct {
	journal.Storage
	fail atomic.Bool
}

func (f *subscriptionSourceFailure) AppendLogsBatchAccepted(ctx context.Context, envelope journal.Envelope, event journal.LogsBatchAccepted) error {
	if err := f.Storage.AppendLogsBatchAccepted(ctx, envelope, event); err != nil {
		return err
	}
	if f.fail.Swap(false) {
		return errors.New("injected failure after Logs batch acceptance append")
	}
	return nil
}

type subscriptionRecovery struct {
	c             *lambdaEventsCloud
	logs          *cloudwatchlogs.Client
	backends      *storage.Backends
	source        *clock.Manual
	sourceFailure *subscriptionSourceFailure
	targetFailure *lambdaAcceptanceFailure
	group, stream string
	filter        string
	permission    eventLogsObservation
}

func (r *subscriptionRecovery) connect(t *testing.T, backends *storage.Backends) {
	t.Helper()
	r.backends = backends
	r.sourceFailure = &subscriptionSourceFailure{Storage: backends.Journal}
	r.targetFailure = &lambdaAcceptanceFailure{Storage: r.sourceFailure}
	backends.Journal = r.targetFailure
	previous := r.c
	r.c = lambdaEventsConnect(t, backends, r.source)
	if previous != nil {
		// Endpoint injection owns transport routing, so durable queue URLs and
		// customer function configuration survive the new server port unchanged.
		r.c.outputURL = previous.outputURL
		r.c.functionName, r.c.functionARN = previous.functionName, previous.functionARN
	}
	r.logs = logsClient(cloudClients{r.c.server}, "test")
}

func (r *subscriptionRecovery) provision(t *testing.T, fixture subscriptionFixture) {
	t.Helper()
	clients := map[string]any{"logs": r.logs, "lambda": r.c.lambda, "sqs": r.c.queues, "iam": (cloudClients{r.c.server}).iam("test", "test", "")}
	for _, label := range []string{"create-collector", "create-group", "create-stream-one", "create-role", "put-owned-policy", "create-function", "permission-global", "global-principal-create"} {
		var selected *eventLogsObservation
		for i := range fixture.Observations {
			row := &fixture.Observations[i]
			if row.Label == label && row.Result.Code == "Success" {
				selected = row
				break
			}
		}
		if selected == nil {
			t.Fatalf("native fixture lacks successful %s", label)
		}
		out := replayEventLogs(t, clients[selected.Service], *selected, func(value any) {
			switch input := value.(type) {
			case *awslambda.CreateFunctionInput:
				input.Environment.Variables["QUEUE_URL"] = strings.Replace(aws.ToString(r.c.outputURL), "127.0.0.1", "host.docker.internal", 1)
				r.c.functionName = input.FunctionName
			case *cloudwatchlogs.CreateLogStreamInput:
				r.group, r.stream = aws.ToString(input.LogGroupName), aws.ToString(input.LogStreamName)
			case *cloudwatchlogs.PutSubscriptionFilterInput:
				r.filter = aws.ToString(input.FilterName)
			}
		})
		switch out := out.(type) {
		case *sqs.CreateQueueOutput:
			r.c.outputURL = out.QueueUrl
		case *awslambda.CreateFunctionOutput:
			r.c.functionARN = aws.ToString(out.FunctionArn)
			if err := awslambda.NewFunctionActiveWaiter(r.c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: r.c.functionName}, time.Minute); err != nil {
				t.Fatal(err)
			}
		}
		if label == "permission-global" {
			r.permission = *selected
		}
	}
}

func (r *subscriptionRecovery) input(message string) *cloudwatchlogs.PutLogEventsInput {
	return &cloudwatchlogs.PutLogEventsInput{LogGroupName: &r.group, LogStreamName: &r.stream, LogEvents: []logtypes.InputLogEvent{{Timestamp: aws.Int64(r.source.Now().UnixMilli()), Message: &message}}}
}

func (r *subscriptionRecovery) journal(t *testing.T) []journal.Event {
	t.Helper()
	rows, err := r.backends.Journal.Read(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func (r *subscriptionRecovery) put(t *testing.T, message string) (subscriptionLogEvent, journal.Event) {
	t.Helper()
	before := make(map[string]bool)
	for _, row := range r.journal(t) {
		before[row.LogsBatchAccepted.BatchID] = true
	}
	input := r.input(message)
	out, err := r.logs.PutLogEvents(t.Context(), input)
	if err != nil || out.RejectedLogEventsInfo != nil {
		t.Fatalf("source ingestion failed: %+v, %v", out, err)
	}
	stored, err := r.logs.FilterLogEvents(t.Context(), &cloudwatchlogs.FilterLogEventsInput{LogGroupName: &r.group, LogStreamNames: []string{r.stream}})
	if err != nil {
		t.Fatal(err)
	}
	var event subscriptionLogEvent
	for _, row := range stored.Events {
		if aws.ToString(row.Message) == message {
			event = subscriptionLogEvent{ID: aws.ToString(row.EventId), Message: aws.ToString(row.Message), Timestamp: aws.ToInt64(row.Timestamp)}
		}
	}
	if event.ID == "" || event.Timestamp != aws.ToInt64(input.LogEvents[0].Timestamp) {
		t.Fatalf("accepted source event missing or changed: %+v", event)
	}
	var batch journal.Event
	for _, row := range r.journal(t) {
		if !before[row.LogsBatchAccepted.BatchID] && row.LogsBatchAccepted.LogGroupARN == "arn:aws:logs:us-east-1:000000000000:log-group:"+r.group && row.LogsBatchAccepted.LogStreamName == r.stream {
			if batch.LogsBatchAccepted.BatchID != "" {
				t.Fatal("single ingestion published multiple accepted batch facts")
			}
			batch = row
		}
	}
	if batch.LogsBatchAccepted.BatchID == "" || batch.LogsBatchAccepted.EventCount != 1 {
		t.Fatalf("accepted source batch fact missing: %+v", batch)
	}
	return event, batch
}

func (r *subscriptionRecovery) receive(t *testing.T, event subscriptionLogEvent, batch journal.Event) {
	t.Helper()
	message := lambdaEventsReceive(t, r.c, r.c.outputURL, 1)[0]
	var record subscriptionRecord
	if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &record); err != nil {
		t.Fatal(err)
	}
	want := subscriptionEnvelope{MessageType: "DATA_MESSAGE", Owner: "000000000000", LogGroup: r.group, LogStream: r.stream, SubscriptionFilters: []string{r.filter}, LogEvents: []subscriptionLogEvent{event}}
	if !reflect.DeepEqual(record.Envelope, want) || record.InvokedFunctionARN != r.c.functionARN || record.HandlerRequestID == "" {
		t.Fatalf("retained subscription changed accepted event bytes/ID: got %+v, want %+v", record, want)
	}
	rows := r.journal(t)
	var invocation journal.Event
	for _, row := range rows {
		if row.LambdaInvocationAccepted.FunctionARN == r.c.functionARN && row.RequestID == record.HandlerRequestID {
			invocation = row
		}
	}
	if invocation.LambdaInvocationAccepted.InvocationID == "" || invocation.ParentEventID != batch.LogsBatchAccepted.BatchID || invocation.Sequence <= batch.Sequence {
		t.Fatalf("real Lambda acceptance lost original batch parent: batch %+v, invocation %+v", batch, invocation)
	}
	for _, row := range rows {
		if row.SQSMessageAccepted.MessageID == aws.ToString(message.MessageId) && row.ParentEventID == invocation.LambdaInvocationAccepted.InvocationID && row.Sequence > invocation.Sequence {
			return
		}
	}
	t.Fatal("real collector message lost its Lambda acceptance parent")
}

func (r *subscriptionRecovery) noInvocation(t *testing.T, batch journal.Event) {
	t.Helper()
	for _, row := range r.journal(t) {
		if row.LambdaInvocationAccepted.FunctionARN == r.c.functionARN && row.ParentEventID == batch.LogsBatchAccepted.BatchID {
			t.Fatalf("rejected or skipped subscription reached Lambda acceptance: %+v", row)
		}
	}
}

func (r *subscriptionRecovery) retry(t *testing.T, batch journal.Event) logstorage.SubscriptionDelivery {
	t.Helper()
	// The shared drain gate waits for the failed target admission and its
	// scheduling transaction, unlike observing only the consumed fault flag.
	trailNativeDrain(t, r.c.cloud)
	if r.targetFailure.fail.Load() {
		t.Fatal("target acceptance fault was not exercised")
	}
	var delivery logstorage.SubscriptionDelivery
	if err := r.backends.Logs.View(t.Context(), func(reader logstorage.Reader) error {
		next, found, err := reader.NextSubscriptionDelivery()
		if err != nil {
			return err
		}
		if !found {
			return errors.New("failed subscription admission lost its retained retry")
		}
		delivery, err = reader.SubscriptionDelivery(next.Key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if delivery.ParentEventID != batch.LogsBatchAccepted.BatchID || !delivery.Due.After(r.source.Now()) || delivery.Attempts != 1 {
		t.Fatalf("failed target admission did not retain the accepted batch: %+v", delivery)
	}
	lambdaEventsQuiet(t, r.c, r.c.outputURL)
	r.noInvocation(t, batch)
	return delivery
}

func (r *subscriptionRecovery) retired(t *testing.T, id string) {
	t.Helper()
	trailNativeDrain(t, r.c.cloud)
	err := r.backends.Logs.View(t.Context(), func(reader logstorage.Reader) error {
		_, err := reader.SubscriptionDelivery(id)
		return err
	})
	if !errors.Is(err, logstorage.ErrNotFound) {
		t.Fatalf("acknowledged or expired subscription payload remains retained: %v", err)
	}
}

func TestLogsSubscriptionDockerRecovery(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real Logs subscription recovery")
	}
	fixture := loadSubscriptionFixture(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := &subscriptionRecovery{source: clock.NewManual(time.UnixMilli(fixture.Observations[0].Started).UTC())}
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "logs-recovery.sqlite")
			var closeDatabase func()
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			r.connect(t, backends)
			r.provision(t, fixture)
			reopen := func() {
				if backend != "sqlite" {
					return
				}
				if err := r.c.cloud.Close(); err != nil {
					t.Fatal(err)
				}
				r.c.server.Close()
				closeDatabase()
				backends, closeDatabase = openSQLiteBackends(t, path)
				r.connect(t, backends)
			}

			// Append succeeded inside the borrowed transaction before the injected
			// error. None of its source records, fact, or downstream work may commit.
			r.sourceFailure.fail.Store(true)
			_, err := r.logs.PutLogEvents(t.Context(), r.input(`{"kind":"accept","case":"source-rollback"}`))
			assertAPIError(t, err, "ServiceUnavailableException")
			if r.sourceFailure.fail.Load() {
				t.Fatal("source append fault was not exercised")
			}
			stored, err := r.logs.FilterLogEvents(t.Context(), &cloudwatchlogs.FilterLogEventsInput{LogGroupName: &r.group})
			if err != nil || len(stored.Events) != 0 {
				t.Fatalf("failed source append committed log rows: %+v, %v", stored, err)
			}
			lambdaEventsQuiet(t, r.c, r.c.outputURL)
			for _, row := range r.journal(t) {
				if row.LogsBatchAccepted.BatchID != "" {
					t.Fatalf("failed source append committed a batch fact: %+v", row)
				}
			}
			if err := r.backends.Logs.View(t.Context(), func(reader logstorage.Reader) error {
				_, found, err := reader.NextSubscriptionDelivery()
				if err == nil && found {
					return errors.New("failed source append retained delivery work")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			event, batch := r.put(t, `{"kind":"accept","case":"after-source-rollback"}`)
			r.receive(t, event, batch)

			r.targetFailure.fail.Store(true)
			event, batch = r.put(t, " {\"kind\":\"accept\",\"case\":\"retained\",\"bytes\":\"雪 \\u0000 \\\"\"} \n")
			retained := r.retry(t, batch)
			if _, err := r.logs.DeleteLogStream(t.Context(), &cloudwatchlogs.DeleteLogStreamInput{LogGroupName: &r.group, LogStreamName: &r.stream}); err != nil {
				t.Fatal(err)
			}
			reopen()
			lambdaEventsQuiet(t, r.c, r.c.outputURL)
			// Retry cadence is modeled local service time, not native jitter.
			advanceClock(t, r.source, retained.Due.Sub(r.source.Now()))
			r.receive(t, event, batch)
			r.retired(t, retained.ID)
			if _, err := r.logs.CreateLogStream(t.Context(), &cloudwatchlogs.CreateLogStreamInput{LogGroupName: &r.group, LogStreamName: &r.stream}); err != nil {
				t.Fatal(err)
			}

			r.targetFailure.fail.Store(true)
			_, expiredBatch := r.put(t, `{"kind":"accept","case":"expired-admission"}`)
			expired := r.retry(t, expiredBatch)
			// Jump directly past the modeled 24-hour admission-retention bound;
			// no intermediate deadline is drained and no retry may reach Lambda.
			advanceClock(t, r.source, 24*time.Hour+time.Second)
			lambdaEventsQuiet(t, r.c, r.c.outputURL)
			r.noInvocation(t, expiredBatch)
			r.retired(t, expired.ID)

			var permission awslambda.AddPermissionInput
			if err := json.Unmarshal(r.permission.Input, &permission); err != nil {
				t.Fatal(err)
			}
			if _, err := r.c.lambda.RemovePermission(t.Context(), &awslambda.RemovePermissionInput{FunctionName: permission.FunctionName, StatementId: permission.StatementId}); err != nil {
				t.Fatal(err)
			}
			disabledAt := r.source.Now()
			_, denied := r.put(t, `{"kind":"accept","case":"permission-revoked"}`)
			trailNativeDrain(t, r.c.cloud)
			lambdaEventsQuiet(t, r.c, r.c.outputURL)
			r.noInvocation(t, denied)
			reopen() // The disabled interval must survive a real SQLite reopen.
			replayEventLogs(t, r.c.lambda, r.permission)
			_, skipped := r.put(t, `{"kind":"accept","case":"permission-restored-but-disabled"}`)
			lambdaEventsQuiet(t, r.c, r.c.outputURL)
			r.noInvocation(t, skipped)
			// Exactly ten service minutes is stackd's disablement model, not a
			// measured AWS deadline or an AWS exactly-once/absence guarantee.
			advanceClock(t, r.source, disabledAt.Add(10*time.Minute-time.Second).Sub(r.source.Now()))
			_, boundarySkipped := r.put(t, `{"kind":"accept","case":"before-disable-deadline"}`)
			lambdaEventsQuiet(t, r.c, r.c.outputURL)
			advanceClock(t, r.source, time.Second)
			event, batch = r.put(t, `{"kind":"accept","case":"after-disable-deadline"}`)
			r.receive(t, event, batch)
			lambdaEventsQuiet(t, r.c, r.c.outputURL)
			for _, absent := range []journal.Event{denied, skipped, boundarySkipped, expiredBatch} {
				r.noInvocation(t, absent)
			}
		})
	}
}
