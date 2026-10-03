package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/journal"
	"stackd/storage"
	lambdastorage "stackd/storage/lambda"
)

type lambdaAcceptanceFailure struct {
	journal.Storage
	fail atomic.Bool
}

func (f *lambdaAcceptanceFailure) AppendLambdaInvocationAccepted(ctx context.Context, envelope journal.Envelope, event journal.LambdaInvocationAccepted) error {
	if err := f.Storage.AppendLambdaInvocationAccepted(ctx, envelope, event); err != nil {
		return err
	}
	if f.fail.Swap(false) {
		return errors.New("injected failure after Lambda acceptance append")
	}
	return nil
}

type lambdaEventsObservation struct {
	Label  string          `json:"label"`
	Input  json.RawMessage `json:"input"`
	Result struct {
		HTTPStatus int               `json:"http_status"`
		Headers    map[string]string `json:"headers"`
	} `json:"result"`
}

type lambdaEventsFixture struct {
	Observations []lambdaEventsObservation `json:"observations"`
}

func (f lambdaEventsFixture) observation(t *testing.T, label string) lambdaEventsObservation {
	t.Helper()
	// The capture includes an initial control-plane attempt and a successful
	// continuation. Replay the final observed request, not the earlier probe.
	for i := len(f.Observations) - 1; i >= 0; i-- {
		if f.Observations[i].Label == label {
			return f.Observations[i]
		}
	}
	t.Fatalf("native Lambda event fixture lacks %s", label)
	return lambdaEventsObservation{}
}

func lambdaEventsInput[T any](t *testing.T, f lambdaEventsFixture, label string) *T {
	t.Helper()
	var input T
	if err := json.Unmarshal(f.observation(t, label).Input, &input); err != nil {
		t.Fatalf("decode native %s request: %v", label, err)
	}
	return &input
}

type lambdaEventsCloud struct {
	repository   lambdastorage.Repository
	cloud        *stackd.Stack
	server       *httptest.Server
	lambda       *awslambda.Client
	events       *eventbridge.Client
	queues       *sqs.Client
	outputURL    *string
	dlqURL       *string
	functionName *string
	functionARN  string
}

func lambdaEventsConnect(t *testing.T, backends *storage.Backends, source clock.Clock) *lambdaEventsCloud {
	t.Helper()
	cloud, server := newLambdaDockerStack(t, stackd.Config{Storage: backends, Clock: source}, nil)
	c := cloudClients{server}
	return &lambdaEventsCloud{
		repository: backends.Lambda,
		cloud:      cloud, server: server, queues: c.sqs("test", "test", ""),
		lambda: awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1}),
		events: eventbridge.New(eventbridge.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1}),
	}
}

func lambdaEventsProvision(t *testing.T, c *lambdaEventsCloud, f lambdaEventsFixture) {
	t.Helper()
	ctx := t.Context()
	for _, queue := range []struct {
		label string
		url   **string
	}{{"create_out", &c.outputURL}, {"create_dlq", &c.dlqURL}} {
		out, err := c.queues.CreateQueue(ctx, lambdaEventsInput[sqs.CreateQueueInput](t, f, queue.label))
		if err != nil {
			t.Fatal(err)
		}
		*queue.url = out.QueueUrl
	}
	root := (cloudClients{c.server}).iam("test", "test", "")
	role, err := root.CreateRole(ctx, lambdaEventsInput[iam.CreateRoleInput](t, f, "create_execution_role"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.PutRolePolicy(ctx, lambdaEventsInput[iam.PutRolePolicyInput](t, f, "execution_sqs_only")); err != nil {
		t.Fatal(err)
	}
	input := lambdaEventsInput[awslambda.CreateFunctionInput](t, f, "create_function_attempt_1")
	input.Role = role.Role.Arn
	input.Environment.Variables["QUEUE_URL"] = strings.Replace(aws.ToString(c.outputURL), "127.0.0.1", "host.docker.internal", 1)
	created, err := c.lambda.CreateFunction(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	c.functionName, c.functionARN = input.FunctionName, aws.ToString(created.FunctionArn)
	if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: c.functionName}, time.Minute); err != nil {
		t.Fatal(err)
	}
}

// Poll real consumer effects using wall time, independently of the manual
// service clock. Advancing service time must never race a handler's completion
// when testing its next nominal retry deadline.
func lambdaEventsReceive(t *testing.T, c *lambdaEventsCloud, url *string, count int) []sqstypes.Message {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var messages []sqstypes.Message
	for len(messages) < count {
		if _, err := c.cloud.RunDueJobs(ctx, 100); err != nil {
			t.Fatal(err)
		}
		out, err := c.queues.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: url, MaxNumberOfMessages: int32(min(10, count-len(messages))), MessageAttributeNames: []string{"All"}})
		if err != nil {
			t.Fatal(err)
		}
		for _, message := range out.Messages {
			if _, err := c.queues.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: url, ReceiptHandle: message.ReceiptHandle}); err != nil {
				t.Fatal(err)
			}
			messages = append(messages, message)
		}
		if len(messages) >= count {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for %d real SQS effects: received %d: %v", count, len(messages), ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	return messages
}

func lambdaEventsQuiet(t *testing.T, c *lambdaEventsCloud, urls ...*string) {
	t.Helper()
	deadline := time.Now().Add(300 * time.Millisecond)
	for {
		if _, err := c.cloud.RunDueJobs(t.Context(), 100); err != nil {
			t.Fatal(err)
		}
		for _, url := range urls {
			out, err := c.queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{
				QueueUrl: url, MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"},
				MessageSystemAttributeNames: []sqstypes.MessageSystemAttributeName{sqstypes.MessageSystemAttributeNameAll},
			})
			if err != nil {
				t.Fatalf("checking unexpected SQS side effects at %s: %v", aws.ToString(url), err)
			}
			if len(out.Messages) != 0 {
				messages, err := json.Marshal(out.Messages)
				if err != nil {
					t.Fatalf("encoding unexpected SQS side effects at %s: %v", aws.ToString(url), err)
				}
				t.Fatalf("unexpected SQS side effects at %s: %s", aws.ToString(url), messages)
			}
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func lambdaEventsAwaitRetry(t *testing.T, c *lambdaEventsCloud, due time.Time, completedRequests ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for {
		_, err := c.cloud.RunDueJobs(ctx, 100)
		if err != nil {
			t.Fatal(err)
		}
		var job lambdastorage.InvocationJob
		var found bool
		var inFlight []lambdastorage.InvocationRecord
		if err := c.repository.View(ctx, func(r lambdastorage.Reader) error {
			var err error
			if len(completedRequests) != 0 {
				inFlight, err = r.InFlightInvocations()
				if err != nil {
					return err
				}
			}
			job, found, err = r.NextInvocation()
			return err
		}); err != nil {
			t.Fatal(err)
		}
		settled := true
		for _, invocation := range inFlight {
			if slices.Contains(completedRequests, invocation.RequestID) {
				settled = false
			}
		}
		if found && job.Due.Equal(due) && settled {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("handlers %v did not settle with retry at %s: next=%+v in-flight=%d", completedRequests, due, job, len(inFlight))
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func lambdaEventsInvoke(t *testing.T, c *lambdaEventsCloud, f lambdaEventsFixture, label string) (string, map[string]any) {
	t.Helper()
	row := f.observation(t, label)
	// CLI Payload is literal JSON, whereas Go SDK []byte JSON decoding expects
	// base64; decode this one transport difference explicitly.
	var native struct{ FunctionName, InvocationType, Payload, LogType, ClientContext, Qualifier string }
	if err := json.Unmarshal(row.Input, &native); err != nil {
		t.Fatal(err)
	}
	input := &awslambda.InvokeInput{FunctionName: c.functionName, InvocationType: lambdatypes.InvocationType(native.InvocationType), Payload: []byte(native.Payload), LogType: lambdatypes.LogType(native.LogType)}
	if native.Qualifier != "" {
		input.Qualifier = aws.String(native.Qualifier)
	}
	if native.ClientContext != "" {
		input.ClientContext = aws.String(native.ClientContext)
	}
	out, err := c.lambda.Invoke(t.Context(), input)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if out.StatusCode != int32(row.Result.HTTPStatus) || len(out.Payload) != 0 || out.FunctionError != nil || out.ExecutedVersion != nil || out.LogResult != nil {
		t.Fatalf("%s asynchronous acceptance: %+v", label, out)
	}
	response, ok := awsmiddleware.GetRawResponse(out.ResultMetadata).(*smithyhttp.Response)
	if !ok {
		t.Fatal("SDK omitted the HTTP response metadata")
	}
	nativeHeaders := make(http.Header)
	for key, value := range row.Result.Headers {
		nativeHeaders.Set(key, value)
	}
	for _, header := range []string{"Content-Length", "Content-Type", "X-Amz-Function-Error", "X-Amz-Executed-Version", "X-Amz-Log-Result"} {
		if got, want := response.Header.Get(header), nativeHeaders.Get(header); got != want {
			t.Fatalf("%s %s = %q, native = %q", label, header, got, want)
		}
	}
	requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
	if !ok || requestID == "" || requestID != response.Header.Get("X-Amzn-RequestId") {
		t.Fatal("asynchronous acceptance lacks its correlation request ID")
	}
	var payload map[string]any
	if err := json.Unmarshal(input.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	return requestID, payload
}

func lambdaEventsRecord(t *testing.T, functionARN string, message sqstypes.Message, requestID string, event map[string]any) string {
	t.Helper()
	var record struct {
		Event         map[string]any  `json:"event"`
		RequestID     string          `json:"aws_request_id"`
		FunctionARN   string          `json:"invoked_function_arn"`
		Version       string          `json:"function_version"`
		ClientContext json.RawMessage `json:"client_context"`
	}
	if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &record); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(record.Event, event) || record.RequestID == "" || (requestID != "" && record.RequestID != requestID) || record.FunctionARN != functionARN || record.Version != "$LATEST" || string(record.ClientContext) != "null" {
		t.Fatalf("customer boto3 record does not preserve native event/context: %s", aws.ToString(message.Body))
	}
	return record.RequestID
}

func TestLambdaDockerAsyncNativeReplay(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	fixture := lambdaFixture[lambdaEventsFixture](t, "event_invocation")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 13, 15, 35, 0, 0, time.UTC))
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "lambda-events.sqlite")
			var closeDatabase func()
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			acceptance := &lambdaAcceptanceFailure{Storage: backends.Journal}
			acceptance.fail.Store(true)
			backends.Journal = acceptance
			c := lambdaEventsConnect(t, backends, source)
			lambdaEventsProvision(t, c, fixture)
			_, err := c.lambda.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: c.functionName, InvocationType: lambdatypes.InvocationTypeEvent, Payload: []byte(`{"case":"failed-acceptance"}`)})
			assertAPIError(t, err, "ServiceException")
			lambdaEventsQuiet(t, c, c.outputURL)
			log, err := acceptance.Read(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range log {
				if event.LambdaInvocationAccepted.InvocationID != "" {
					t.Fatalf("failed acceptance escaped into the committed journal: %+v", event)
				}
			}
			for _, label := range []string{"async_success", "async_invalid_client_context"} {
				requestID, payload := lambdaEventsInvoke(t, c, fixture, label)
				lambdaEventsRecord(t, c.functionARN, lambdaEventsReceive(t, c, c.outputURL, 1)[0], requestID, payload)
			}
			requestID, payload := lambdaEventsInvoke(t, c, fixture, "async_function_error_default_retry")
			for attempt := range 3 {
				lambdaEventsRecord(t, c.functionARN, lambdaEventsReceive(t, c, c.outputURL, 1)[0], requestID, payload)
				if attempt == 2 {
					break
				}
				delay := time.Duration(attempt+1) * time.Minute
				lambdaEventsAwaitRetry(t, c, source.Now().Add(delay))
				if backend == "sqlite" && attempt == 0 {
					// Upgrade an SDK-created retry from the previous schema. The
					// remaining attempts must preserve both identity and retry budget.
					if err := c.cloud.Close(); err != nil {
						t.Fatal(err)
					}
					c.server.Close()
					historicalPath := filepath.Join(t.TempDir(), "version43.sqlite")
					historical := awstest.HistoricalSQLite(t, historicalPath, "../storage/sqlite/schema", 43, path, map[string]string{"lambda_functions": historicalLambdaFunctions})
					if err := historical.Close(); err != nil {
						t.Fatal(err)
					}
					closeDatabase()
					path = historicalPath
					backends, closeDatabase = openSQLiteBackends(t, path)
					previous := c
					c = lambdaEventsConnect(t, backends, source)
					c.functionName, c.functionARN = previous.functionName, previous.functionARN
					// Endpoint injection redirects both host SDK and customer boto3;
					// durable queue URLs and function configuration need no rewrite.
					c.outputURL, c.dlqURL = previous.outputURL, previous.dlqURL
					lambdaEventsAwaitRetry(t, c, source.Now().Add(delay))
				}
				advanceClock(t, source, delay-time.Second)
				lambdaEventsQuiet(t, c, c.outputURL)
				advanceClock(t, source, time.Second)
			}
			// Native evidence establishes three deliveries, not an exact AWS
			// wall-time SLA. The 60/120 boundaries above are local modeled time.
			lambdaEventsQuiet(t, c, c.outputURL)
			advanceClock(t, source, 10*time.Minute)
			lambdaEventsQuiet(t, c, c.outputURL)
			lambdaEventsPipeline(t, c, fixture, source)
		})
	}
}

func lambdaEventsPipeline(t *testing.T, c *lambdaEventsCloud, f lambdaEventsFixture, source *clock.Manual) {
	t.Helper()
	ctx := t.Context()
	for _, label := range []string{"create_rule_good", "create_rule_bad"} {
		if _, err := c.events.PutRule(ctx, lambdaEventsInput[eventbridge.PutRuleInput](t, f, label)); err != nil {
			t.Fatal(err)
		}
	}
	policy := lambdaEventsInput[sqs.SetQueueAttributesInput](t, f, "dlq_eventbridge_policy")
	policy.QueueUrl = c.dlqURL
	if _, err := c.queues.SetQueueAttributes(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := c.lambda.AddPermission(ctx, lambdaEventsInput[awslambda.AddPermissionInput](t, f, "grant_good_rule")); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"target_good", "target_bad"} {
		input := lambdaEventsInput[eventbridge.PutTargetsInput](t, f, label)
		out, err := c.events.PutTargets(ctx, input)
		if err != nil || out.FailedEntryCount != 0 || len(out.FailedEntries) != 0 {
			t.Fatalf("native Lambda target with SqsParameters rejected: %+v, %v", out, err)
		}
		listed, err := c.events.ListTargetsByRule(ctx, &eventbridge.ListTargetsByRuleInput{Rule: input.Rule})
		if err != nil || len(listed.Targets) != 1 || !reflect.DeepEqual(listed.Targets[0].SqsParameters, input.Targets[0].SqsParameters) {
			t.Fatalf("Lambda target parameters not retained: %+v, %v", listed, err)
		}
	}
	for _, route := range []string{"good", "bad"} {
		input := lambdaEventsInput[eventbridge.PutEventsInput](t, f, "put_event_"+route)
		out, err := c.events.PutEvents(ctx, input)
		if err != nil || out.FailedEntryCount != 0 || len(out.Entries) != 1 || aws.ToString(out.Entries[0].EventId) == "" {
			t.Fatalf("PutEvents %s: %+v, %v", route, out, err)
		}
		var detail map[string]any
		if err := json.Unmarshal([]byte(aws.ToString(input.Entries[0].Detail)), &detail); err != nil {
			t.Fatal(err)
		}
		envelope := map[string]any{"version": "0", "id": aws.ToString(out.Entries[0].EventId), "detail-type": aws.ToString(input.Entries[0].DetailType), "source": aws.ToString(input.Entries[0].Source), "account": "000000000000", "region": "us-east-1", "time": source.Now().Format(time.RFC3339), "resources": []any{}, "detail": detail}
		if route == "good" {
			lambdaRequestID := lambdaEventsRecord(t, c.functionARN, lambdaEventsReceive(t, c, c.outputURL, 1)[0], "", envelope)
			putRequestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
			if !ok || putRequestID == "" || lambdaRequestID == putRequestID {
				t.Fatalf("Lambda invocation reused the originating PutEvents request ID: Lambda=%q, PutEvents=%q", lambdaRequestID, putRequestID)
			}
			lambdaEventsQuiet(t, c, c.dlqURL)
			continue
		}
		message := lambdaEventsReceive(t, c, c.dlqURL, 1)[0]
		var rejected map[string]any
		if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &rejected); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rejected, envelope) {
			t.Fatalf("wrong-rule DLQ lost the accepted event ID/payload: %s", aws.ToString(message.Body))
		}
		for name, want := range map[string]string{"ERROR_CODE": "NO_PERMISSIONS", "RULE_ARN": "arn:aws:events:us-east-1:000000000000:rule/stackd-lambda-event-owned-bad", "TARGET_ARN": c.functionARN} {
			attribute := message.MessageAttributes[name]
			if aws.ToString(attribute.DataType) != "String" || aws.ToString(attribute.StringValue) != want {
				t.Fatalf("wrong-rule DLQ %s: %+v, want %q", name, attribute, want)
			}
		}
		lambdaEventsQuiet(t, c, c.outputURL, c.dlqURL)
	}
}
