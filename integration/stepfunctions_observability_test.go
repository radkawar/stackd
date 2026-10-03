package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go/middleware"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	sfnstore "stackd/storage/stepfunctions"
)

type stepFunctionsObservabilityObservation struct {
	Label, Service, Operation string
	Request                   json.RawMessage
	Response                  struct {
		Code   string
		Output json.RawMessage
	}
}

type stepFunctionsObservabilityFixture struct {
	Account      string `json:"caller_account"`
	Region       string
	Started      time.Time `json:"started_at"`
	Observations []stepFunctionsObservabilityObservation
	Caller       struct {
		Output struct {
			ARN string `json:"Arn"`
		}
	}
	Owned struct {
		Executions []struct {
			Case, Kind, ARN, Status string
		}
		Queue struct{ URL string }
	} `json:"owned_resources"`
	Collected struct {
		Logs        []struct{ Raw struct{ Message string } }
		EventBridge []struct{ Envelope map[string]any }
		CloudTrail  []struct {
			Raw struct{ CloudTrailEvent string }
		}
	}
}

type stepFunctionsObservabilityReplay struct {
	fixture    *stepFunctionsObservabilityFixture
	clients    cloudClients
	clock      *clock.Manual
	repository sfnstore.Repository
	queueURL   string
}

type stepFunctionsObservabilityReply struct {
	value any
	body  map[string]any
}

// The source fixture contains eight executions, not eight independent revision
// updates: express-error-data-fail selected the previous Pass/ALL,false revision.
// Replay that observed execution against its captured effective configuration;
// deliberately omit its propagation-raced update, not its successful outcome.
// This does not establish Express ERROR filtering or update propagation parity.
func TestStepFunctionsNativeObservabilityConsumers(t *testing.T) {
	var fixture stepFunctionsObservabilityFixture
	awsReadFixture(t, "stepfunctions/observability.json", &fixture)
	if len(fixture.Owned.Executions) == 0 {
		t.Fatal("native observability fixture has no executions")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := &stepFunctionsObservabilityReplay{fixture: &fixture, clock: clock.NewManual(fixture.Started)}
			var reopen func() cloudClients
			r.clients, reopen = retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: r.clock}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				r.repository = config.Storage.StepFunctions
				return startPublicCloud(t, config)
			})
			// The captured trust policy names the native caller, which predates
			// this fixture's owned resources. Materialize that real IAM principal.
			caller := strings.Split(fixture.Caller.Output.ARN, "/")
			if _, err := r.clients.iam(fixture.Account, "test", "").CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(caller[len(caller)-1])}); err != nil {
				t.Fatal(err)
			}
			for _, label := range []string{
				"create-owned-log-group", "create-owned-resource-scoped-log-policy",
				"create-owned-role", "put-owned-role-permissions",
				"create-standard-machine", "create-express-machine",
				"create-owned-event-queue", "create-owned-status-rule",
				"allow-only-owned-rule", "attach-owned-event-target",
			} {
				r.call(t, r.observation(t, label))
			}
			type observedExecution struct {
				arn               string
				started, terminal map[string]any
			}
			retained := make(map[string]observedExecution)
			cursor := 0
			for index, execution := range fixture.Owned.Executions {
				if !t.Run(execution.Case, func(t *testing.T) {
					start := r.observation(t, execution.Case+"-start")
					for cursor < len(fixture.Observations) {
						row := fixture.Observations[cursor]
						cursor++
						if row.Label == start.Label {
							break
						}
						if row.Operation == "update_state_machine" && row.Label != "express-update-fail-ERROR-True" {
							r.call(t, row)
						}
					}
					var nativeStart map[string]any
					awsDecodeJSON(t, start.Response.Output, &nativeStart)
					at := stepFunctionsObservabilityTime(t, nativeStart["startDate"])
					if at.After(r.clock.Now()) {
						advanceClock(t, r.clock, at.Sub(r.clock.Now()))
					}
					started := r.call(t, start)
					actualARN, ok := started.body["executionArn"].(string)
					if !ok || actualARN == "" {
						t.Fatal("source execution has no ARN", started.body)
					}
					if index == 0 {
						// Reopen after admission without consuming downstream data.
						// Automatic workers may already have progressed; both pending
						// source work and already-delivered consumer records must survive.
						r.clients = reopen()
						r.refreshQueue(t)
					}
					terminal := started
					var nativeTerminal map[string]any
					if execution.Kind == "standard" {
						r.drain(t)
						if execution.Status == "ABORTED" {
							stop := r.observation(t, execution.Case+"-stop")
							stopped := r.call(t, stop)
							r.audit(t, stop, stopped)
						}
						for {
							r.drain(t)
							row := r.observation(t, execution.Case+"-describe")
							terminal = r.call(t, row)
							if terminal.body["status"] != "RUNNING" {
								awsDecodeJSON(t, row.Response.Output, &nativeTerminal)
								break
							}
							if !r.next(t) {
								t.Fatal("running execution has no retained transition")
							}
						}
						r.audit(t, start, started)
					} else {
						awsDecodeJSON(t, start.Response.Output, &nativeTerminal)
					}
					for _, key := range []string{"status", "name", "stateMachineArn", "input", "inputDetails", "output", "outputDetails", "error", "cause"} {
						want, wantPresent := nativeTerminal[key]
						got, gotPresent := terminal.body[key]
						if wantPresent != gotPresent {
							t.Fatalf("%s presence: native=%t local=%t", key, wantPresent, gotPresent)
						}
						stepFunctionsObservabilityEqual(t, key, want, got)
					}
					r.drain(t)
					r.compareLogs(t, execution.ARN, actualARN, started.body, terminal.body)
					r.compareEvents(t, execution.ARN, actualARN, execution.Kind, started.body, terminal.body)
					retained[execution.ARN] = observedExecution{actualARN, started.body, terminal.body}
					if execution.Case == "express-error-data-fail" {
						t.Log("captured effective prior Pass/ALL,false execution only; express-update-fail-ERROR-True and its config read are not replayed")
					}
				}) {
					return
				}
			}
			// Retain both already-ingested history and source-owned metric state.
			// A fresh service graph must not republish execution counter samples.
			r.clients = reopen()
			r.refreshQueue(t)
			advanceClock(t, r.clock, 2*time.Minute)
			r.drain(t)
			if len(r.receiveEvents(t)) != 0 {
				t.Fatal("completed status delivery repeated after reopen")
			}
			for nativeARN, execution := range retained {
				r.compareLogs(t, nativeARN, execution.arn, execution.started, execution.terminal)
			}
			for _, row := range fixture.Observations {
				if strings.HasPrefix(row.Label, "metrics-final-") {
					t.Run(row.Label, func(t *testing.T) { r.metrics(t, row) })
				}
			}
			// LookupEvents is a management-event consumer, not proof that data
			// calls are unaudited. This capture created no trail/data selector.
			trails := organizationTrailClient(r.clients, fixture.Account, fixture.Region)
			out, err := trails.LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("StartSyncExecution")}}})
			if err != nil || len(out.Events) != 0 {
				t.Fatalf("synchronous Express leaked into management history: %+v %v", out, err)
			}
			t.Log("omitted native wall-clock magnitudes, Express allocator/billing-memory values, Express ERROR propagation race, and unrecorded StartSyncExecution data-selector delivery; metric sample counts/units are not full observability parity")
		})
	}
}

// Duplicate describe labels are native poll samples: select the last response,
// not the provider's observed convergence latency.
func (r *stepFunctionsObservabilityReplay) observation(t *testing.T, label string) stepFunctionsObservabilityObservation {
	t.Helper()
	for index := len(r.fixture.Observations) - 1; index >= 0; index-- {
		if row := r.fixture.Observations[index]; row.Label == label {
			return row
		}
	}
	t.Fatal("missing native observation", label)
	return stepFunctionsObservabilityObservation{}
}

func (r *stepFunctionsObservabilityReplay) call(t *testing.T, row stepFunctionsObservabilityObservation) stepFunctionsObservabilityReply {
	t.Helper()
	wire := &awstest.WireClient{Client: r.clients.server.Client()}
	endpoint := aws.String(r.clients.server.URL)
	identity := credentials.NewStaticCredentialsProvider(r.fixture.Account, "test", "")
	var client any
	switch row.Service {
	case "iam":
		client = r.clients.iam(r.fixture.Account, "test", "")
	case "logs":
		client = cloudwatchlogs.New(cloudwatchlogs.Options{Region: r.fixture.Region, BaseEndpoint: endpoint, Credentials: identity, HTTPClient: wire, RetryMaxAttempts: 1})
	case "events":
		client = eventbridge.New(eventbridge.Options{Region: r.fixture.Region, BaseEndpoint: endpoint, Credentials: identity, HTTPClient: wire, RetryMaxAttempts: 1})
	case "sqs":
		client = sqs.New(sqs.Options{Region: r.fixture.Region, BaseEndpoint: endpoint, Credentials: identity, HTTPClient: wire, RetryMaxAttempts: 1})
	case "cloudwatch":
		client = cloudwatch.New(cloudwatch.Options{Region: r.fixture.Region, BaseEndpoint: endpoint, Credentials: identity, HTTPClient: wire, RetryMaxAttempts: 1})
	case "sfn":
		client = sfn.New(sfn.Options{Region: r.fixture.Region, BaseEndpoint: endpoint, Credentials: identity, HTTPClient: wire, RetryMaxAttempts: 1,
			APIOptions: []func(*middleware.Stack) error{stepFunctionsLocalEndpoint}})
	default:
		t.Fatal("unmapped observability service", row.Service)
	}
	input := row.Request
	if row.Service == "sqs" && r.queueURL != "" {
		input = json.RawMessage(strings.ReplaceAll(string(input), r.fixture.Owned.Queue.URL, r.queueURL))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var output any
	var err error
	operation := strings.ReplaceAll(row.Operation, "_", "")
	if row.Operation == "start_sync_execution" {
		type result struct {
			output any
			err    error
		}
		done := make(chan result, 1)
		go func() { out, callErr := awstest.CallSDK(ctx, client, operation, input); done <- result{out, callErr} }()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
	wait:
		for {
			select {
			case got := <-done:
				output, err = got.output, got.err
				break wait
			case <-ticker.C:
				r.drain(t)
				r.next(t)
			case <-ctx.Done():
				t.Fatal("synchronous native workflow did not settle", ctx.Err())
			}
		}
	} else {
		output, err = awstest.CallSDK(ctx, client, operation, input)
	}
	var native awsNativeObservation
	native.Label, native.Result.Code = row.Label, row.Response.Code
	awsNativeResult(t, native, err)
	reply := stepFunctionsObservabilityReply{value: output}
	if err == nil && row.Service == "sfn" {
		awsDecodeJSON(t, wire.Body, &reply.body)
		if wire.Status != 200 {
			t.Fatalf("%s returned HTTP %d", row.Label, wire.Status)
		}
	}
	if queue, ok := output.(*sqs.CreateQueueOutput); ok && err == nil {
		r.queueURL = aws.ToString(queue.QueueUrl)
	}
	if targets, ok := output.(*eventbridge.PutTargetsOutput); ok && err == nil && targets.FailedEntryCount != 0 {
		t.Fatal("native status destination rejected", targets.FailedEntries)
	}
	return reply
}

func (r *stepFunctionsObservabilityReplay) drain(t *testing.T) {
	t.Helper()
	trailNativeDrain(t, r.clients.server.Config.Handler.(*stackd.Stack))
}

// Advance only to real persisted source work. In particular, never turn a
// completed Express response race into a jump to its retention-expiry date.
func (r *stepFunctionsObservabilityReplay) next(t *testing.T) bool {
	t.Helper()
	var work sfnstore.WorkRecord
	err := r.repository.View(t.Context(), func(reader sfnstore.Reader) error {
		var err error
		work, err = reader.NextWork()
		return err
	})
	if errors.Is(err, sfnstore.ErrNotFound) || err == nil && work.Kind == sfnstore.WorkExecutionExpiry {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	if work.Due.After(r.clock.Now()) {
		advanceClock(t, r.clock, work.Due.Sub(r.clock.Now()))
	}
	return true
}

func (r *stepFunctionsObservabilityReplay) refreshQueue(t *testing.T) {
	t.Helper()
	row := r.observation(t, "create-owned-event-queue")
	var input struct{ QueueName string }
	awsDecodeJSON(t, row.Request, &input)
	out, err := r.queues().GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: &input.QueueName})
	if err != nil {
		t.Fatal(err)
	}
	r.queueURL = aws.ToString(out.QueueUrl)
}

func (r *stepFunctionsObservabilityReplay) queues() *sqs.Client {
	return sqs.New(sqs.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(r.fixture.Account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
}

func (r *stepFunctionsObservabilityReplay) receiveEvents(t *testing.T) []map[string]any {
	t.Helper()
	client := r.queues()
	var events []map[string]any
	for range 20 {
		out, err := client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: &r.queueURL, MaxNumberOfMessages: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Messages) == 0 {
			return events
		}
		for _, message := range out.Messages {
			var envelope map[string]any
			awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &envelope)
			events = append(events, envelope)
			if _, err := client.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: &r.queueURL, ReceiptHandle: message.ReceiptHandle}); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Fatal("status queue did not drain")
	return nil
}

func (r *stepFunctionsObservabilityReplay) logRecords(t *testing.T, executionARN string) map[string]map[string]any {
	t.Helper()
	row := r.observation(t, "create-owned-log-group")
	var input struct{ LogGroupName string }
	awsDecodeJSON(t, row.Request, &input)
	client := cloudwatchlogs.New(cloudwatchlogs.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(r.fixture.Account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
	pages := cloudwatchlogs.NewFilterLogEventsPaginator(client, &cloudwatchlogs.FilterLogEventsInput{LogGroupName: &input.LogGroupName})
	found := map[string]map[string]any{}
	for pages.HasMorePages() {
		page, err := pages.NextPage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range page.Events {
			var record map[string]any
			if json.Unmarshal([]byte(aws.ToString(event.Message)), &record) != nil || record["execution_arn"] != executionARN {
				continue // Native subscription-validation messages are not history.
			}
			id, ok := record["id"].(string)
			stamp, stampOK := record["event_timestamp"].(string)
			millis, err := strconv.ParseInt(stamp, 10, 64)
			if !ok || !stampOK || err != nil || event.Timestamp == nil || millis != *event.Timestamp {
				t.Fatal("log record lost native string IDs/timestamp correlation", record, event)
			}
			if previous, exists := found[id]; exists {
				stepFunctionsObservabilityEqual(t, "duplicate log", previous, record)
			}
			found[id] = record
		}
	}
	return found
}

func (r *stepFunctionsObservabilityReplay) compareLogs(t *testing.T, nativeARN, actualARN string, started, terminal map[string]any) {
	t.Helper()
	want := map[string]map[string]any{}
	for _, entry := range r.fixture.Collected.Logs {
		var record map[string]any
		if json.Unmarshal([]byte(entry.Raw.Message), &record) == nil && record["execution_arn"] == nativeARN {
			want[record["id"].(string)] = record
		}
	}
	got := r.logRecords(t, actualARN)
	if len(got) != len(want) {
		t.Fatalf("execution log filtering: native=%v local=%v", want, got)
	}
	start, stop := stepFunctionsObservabilityTime(t, started["startDate"]), stepFunctionsObservabilityTime(t, terminal["stopDate"])
	for id, expected := range want {
		actual, ok := got[id]
		if !ok {
			t.Fatal("missing captured log event", expected)
		}
		stamp, _ := strconv.ParseInt(actual["event_timestamp"].(string), 10, 64)
		if stamp < start.UnixMilli() || stamp > stop.UnixMilli() {
			t.Fatal("history timestamp escaped source execution", actual)
		}
		delete(expected, "event_timestamp")
		delete(actual, "event_timestamp")
		expected["execution_arn"] = actualARN
		stepFunctionsObservabilityEqual(t, "log "+id, expected, actual)
	}
}

func (r *stepFunctionsObservabilityReplay) compareEvents(t *testing.T, nativeARN, actualARN, kind string, started, terminal map[string]any) {
	t.Helper()
	expected := map[string]map[string]any{}
	var running map[string]any
	for _, entry := range r.fixture.Collected.EventBridge {
		detail := entry.Envelope["detail"].(map[string]any)
		if detail["status"] == "RUNNING" {
			running = entry.Envelope
		}
		if detail["executionArn"] == nativeARN {
			expected[detail["status"].(string)] = entry.Envelope
		}
	}
	if kind == "standard" && expected["RUNNING"] == nil {
		// Native best-effort collection missed this one RUNNING message.
		// Use its positively captured sibling shape, rebound to this start;
		// never interpret bounded collection absence as source suppression.
		if running == nil {
			t.Fatal("fixture has no positive Standard RUNNING evidence")
		}
		expected["RUNNING"] = running
	}
	seen := map[string]bool{}
	for _, event := range r.receiveEvents(t) {
		detail, ok := event["detail"].(map[string]any)
		if !ok || detail["executionArn"] != actualARN {
			t.Fatal("status destination received another execution", event)
		}
		status, _ := detail["status"].(string)
		native, ok := expected[status]
		if !ok || kind == "express" {
			t.Fatal("unrecorded or Express status publication", event)
		}
		id, idOK := event["id"].(string)
		if !idOK || id == "" {
			t.Fatal("status envelope lost event identity", event)
		}
		want := stepFunctionsObservabilityClone(t, native)
		wantDetail := want["detail"].(map[string]any)
		want["resources"] = []any{actualARN}
		wantDetail["executionArn"], wantDetail["name"], wantDetail["input"] = actualARN, terminal["name"], terminal["input"]
		wantDetail["startDate"] = float64(stepFunctionsObservabilityTime(t, started["startDate"]).UnixMilli())
		at := stepFunctionsObservabilityTime(t, started["startDate"])
		if status != "RUNNING" {
			at = stepFunctionsObservabilityTime(t, terminal["stopDate"])
			wantDetail["stopDate"] = float64(at.UnixMilli())
		}
		stamp, ok := event["time"].(string)
		parsed, err := time.Parse(time.RFC3339, stamp)
		if !ok || err != nil || !parsed.Equal(at.Truncate(time.Second)) {
			t.Fatal("status envelope lost source transition time", event)
		}
		delete(want, "id")
		delete(event, "id")
		delete(want, "time")
		delete(event, "time")
		stepFunctionsObservabilityEqual(t, "status "+status, want, event)
		seen[status] = true // Native source delivery is not an ordering guarantee.
	}
	for status := range expected {
		if !seen[status] {
			t.Fatal("missing captured source status at SQS destination", status)
		}
	}
}

func (r *stepFunctionsObservabilityReplay) metrics(t *testing.T, row stepFunctionsObservabilityObservation) {
	t.Helper()
	var query cloudwatch.GetMetricStatisticsInput
	var native cloudwatch.GetMetricStatisticsOutput
	if err := awstest.DecodeSDK(row.Request, &query); err != nil {
		t.Fatal(err)
	}
	if err := awstest.DecodeSDK(row.Response.Output, &native); err != nil {
		t.Fatal(err)
	}
	got := r.call(t, row).value.(*cloudwatch.GetMetricStatisticsOutput)
	actual, actualUnit := ebMetricStatistics(t, got.Datapoints)
	expected, expectedUnit := ebMetricStatistics(t, native.Datapoints)
	if aws.ToString(got.Label) != aws.ToString(native.Label) || actualUnit != expectedUnit || actual[1] != expected[1] {
		t.Fatalf("source metric identity/unit/samples: native=%+v local=%+v", native, got)
	}
	if strings.HasPrefix(aws.ToString(query.MetricName), "Executions") {
		for index := range actual {
			if math.Abs(actual[index]-expected[index]) > 1e-9 {
				t.Fatalf("source transition statistics: native=%v local=%v", expected, actual)
			}
		}
	}
	// ExecutionTime and Express billing/allocator magnitudes are intentionally
	// not compared or replaced by local estimates; their units and sample
	// populations still come from the native source-owned observations.
}

func (r *stepFunctionsObservabilityReplay) audit(t *testing.T, row stepFunctionsObservabilityObservation, reply stepFunctionsObservabilityReply) {
	t.Helper()
	var requestID string
	var operation string
	switch output := reply.value.(type) {
	case *sfn.StartExecutionOutput:
		requestID, _ = awsmiddleware.GetRequestIDMetadata(output.ResultMetadata)
		operation = "StartExecution"
	case *sfn.StopExecutionOutput:
		requestID, _ = awsmiddleware.GetRequestIDMetadata(output.ResultMetadata)
		operation = "StopExecution"
	default:
		t.Fatal("unsupported native audit correlation", row.Label)
	}
	var response struct {
		ResponseMetadata struct {
			RequestID string `json:"RequestId"`
		}
	}
	awsDecodeJSON(t, row.Response.Output, &response)
	var native map[string]any
	for _, entry := range r.fixture.Collected.CloudTrail {
		var record map[string]any
		awsDecodeJSON(t, []byte(entry.Raw.CloudTrailEvent), &record)
		if record["requestID"] == response.ResponseMetadata.RequestID {
			native = record
			break
		}
	}
	if native == nil || requestID == "" {
		t.Fatal("native/local management call lacks request correlation", row.Label)
	}
	r.drain(t)
	got := auditLookupRecord(t, organizationTrailClient(r.clients, r.fixture.Account, r.fixture.Region), requestID, operation)
	for _, key := range []string{"eventSource", "eventName", "eventCategory", "managementEvent", "readOnly", "awsRegion", "recipientAccountId", "requestParameters"} {
		stepFunctionsObservabilityEqual(t, "audit "+key, native[key], got[key])
	}
	wantResponse := native["responseElements"].(map[string]any)
	for _, key := range []string{"startDate", "stopDate"} {
		if _, present := wantResponse[key]; present {
			wantResponse[key] = stepFunctionsObservabilityTime(t, reply.body[key]).UTC().Format(time.RFC3339)
		}
	}
	stepFunctionsObservabilityEqual(t, "audit response", wantResponse, got["responseElements"])
}

func stepFunctionsObservabilityTime(t *testing.T, value any) time.Time {
	t.Helper()
	switch value := value.(type) {
	case string:
		at, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			t.Fatal(err)
		}
		return at
	case float64:
		return time.UnixMilli(int64(math.Round(value * 1000)))
	default:
		t.Fatalf("missing execution timestamp: %T %v", value, value)
		return time.Time{}
	}
}

func stepFunctionsObservabilityClone(t *testing.T, object map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var copy map[string]any
	awsDecodeJSON(t, body, &copy)
	return copy
}

// Compare captured field presence, nulls, scalar types, and complete payloads.
// JSON-bearing input/output strings remain strings but ignore object-key order.
func stepFunctionsObservabilityEqual(t *testing.T, path string, want, got any) {
	t.Helper()
	switch expected := want.(type) {
	case map[string]any:
		actual, ok := got.(map[string]any)
		if !ok || len(actual) != len(expected) {
			t.Fatalf("%s fields: native=%v local=%v", path, expected, got)
		}
		for key, value := range expected {
			other, present := actual[key]
			if !present {
				t.Fatalf("%s missing native field %s", path, key)
			}
			stepFunctionsObservabilityEqual(t, path+"."+key, value, other)
		}
	case string:
		actual, ok := got.(string)
		if !ok {
			t.Fatalf("%s native string, local %T", path, got)
		}
		if (path == "input" || path == "output" || strings.HasSuffix(path, ".input") || strings.HasSuffix(path, ".output")) && json.Valid([]byte(expected)) {
			eventWorkflowJSONEqual(t, actual, expected)
		} else if actual != expected {
			t.Fatalf("%s native=%q local=%q", path, expected, actual)
		}
	default:
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s native=%v local=%v", path, want, got)
		}
	}
}
