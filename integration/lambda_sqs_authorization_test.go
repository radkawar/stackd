package stackd_test

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"stackd/storage"
)

type lambdaSQSAuthorizationEvent struct {
	RequestID          string         `json:"requestId"`
	InvokedFunctionARN string         `json:"invokedFunctionArn"`
	Event              map[string]any `json:"event"`
}

type lambdaSQSAuthorizationSends struct {
	RequestID string `json:"requestId"`
	Sends     []struct {
		Label, Code, Message string
		Input                sqs.SendMessageInput
		Output               struct {
			MessageID string `json:"MessageId"`
		}
	}
}

type lambdaSQSAuthorizationEvidence struct {
	Name   string
	Events []struct{ Data lambdaSQSAuthorizationEvent } `json:"runtime_events"`
	Sends  []struct{ Data lambdaSQSAuthorizationSends } `json:"runtime_sends"`
}

type lambdaSQSAuthorizationRun struct {
	lambdaSQSControlRun
	FatalError json.RawMessage                  `json:"fatal_error"`
	Evidence   []lambdaSQSAuthorizationEvidence `json:"derived_evidence"`
}

// Admission inputs are replayed against fresh roles, never an in-place policy
// mutation. The cleaned setup-aborted run and transient principal-propagation
// errors are retained evidence, not local delivery or sleep requirements.
func TestLambdaSQSAuthorizationDockerNativeSDK(t *testing.T) {
	lambdaURLDocker(t)
	fixture := lambdaFixture[struct{ Runs []lambdaSQSAuthorizationRun }](t, "sqs_mapping_authorization")
	for _, backend := range []string{"memory", "sqlite"} {
		for _, run := range fixture.Runs {
			if len(run.FatalError) != 0 && string(run.FatalError) != "null" {
				continue
			}
			for _, evidence := range run.Evidence {
				t.Run(backend+"/"+evidence.Name, func(t *testing.T) {
					backends := storage.NewMemory()
					if backend == "sqlite" {
						backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "sqs-authorization.sqlite"))
					}
					r := newLambdaSQSControlReplay(run.lambdaSQSControlRun)
					r.connect(t, backends)
					lambdaSQSAuthorizationReplay(t, r, evidence)
				})
			}
		}
	}
}

func lambdaSQSAuthorizationReplay(t *testing.T, r *lambdaSQSControlReplay, native lambdaSQSAuthorizationEvidence) {
	t.Helper()
	root := cloudClients{r.c.server}
	waiter := &lambdaSQSDeliveryReplay{c: r.c, clock: r.clock}
	var sourceID, sourceBody string
	var directRequest string
	var visibility time.Duration
	for _, row := range r.fixture.Observations {
		owned := strings.HasPrefix(row.Label, native.Name+"_")
		if !owned && row.Label != "sink-equals_create_queue" && row.Label != "sink-absent_create_queue" {
			continue
		}
		var err error
		switch {
		case row.Operation == "create_queue" && row.Phase == "setup":
			input := lambdaSQSNativeInput[sqs.CreateQueueInput](t, row.Input, r.normalize())
			var out *sqs.CreateQueueOutput
			out, err = r.c.queues.CreateQueue(t.Context(), &input)
			if err == nil {
				r.replacements = append(r.replacements, row.Result.Output["QueueUrl"].(string), aws.ToString(out.QueueUrl))
				if owned {
					waiter.queueURL = out.QueueUrl
					seconds, e := strconv.Atoi(input.Attributes["VisibilityTimeout"])
					if e != nil {
						t.Fatal(e)
					}
					visibility = time.Duration(seconds) * time.Second
				}
			}
		case row.Operation == "create_role" && row.Phase == "setup":
			input := lambdaSQSNativeInput[iam.CreateRoleInput](t, row.Input, r.normalize())
			_, err = root.iam("test", "test", "").CreateRole(t.Context(), &input)
		case row.Operation == "put_role_policy" && row.Phase == "setup":
			input := lambdaSQSNativeInput[iam.PutRolePolicyInput](t, row.Input, r.normalize())
			_, err = root.iam("test", "test", "").PutRolePolicy(t.Context(), &input)
		case row.Operation == "create_log_group" && row.Phase == "setup":
			input := lambdaSQSNativeInput[cloudwatchlogs.CreateLogGroupInput](t, row.Input, r.normalize())
			_, err = logsClient(root, "test").CreateLogGroup(t.Context(), &input)
		case row.Operation == "set_queue_attributes" && row.Result.Code == "Success":
			input := lambdaSQSNativeInput[sqs.SetQueueAttributesInput](t, row.Input, r.normalize())
			_, err = r.c.queues.SetQueueAttributes(t.Context(), &input)
		case row.Operation == "create_function":
			input := lambdaSQSNativeInput[awslambda.CreateFunctionInput](t, row.Input, r.normalize())
			if input.Environment != nil {
				for name, url := range input.Environment.Variables {
					input.Environment.Variables[name] = strings.Replace(url, "127.0.0.1", "host.docker.internal", 1)
				}
			}
			var out *awslambda.CreateFunctionOutput
			out, err = r.c.lambda.CreateFunction(t.Context(), &input)
			if err == nil {
				r.c.functionName, r.c.functionARN = input.FunctionName, aws.ToString(out.FunctionArn)
				err = awslambda.NewFunctionActiveWaiter(r.c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: input.FunctionName}, time.Minute)
			}
		case row.Operation == "invoke" && row.Phase == "direct-code-context":
			input := lambdaSQSNativeInput[awslambda.InvokeInput](t, row.Input, r.normalize())
			var out *awslambda.InvokeOutput
			out, err = r.c.lambda.Invoke(t.Context(), &input)
			if err == nil {
				if out.FunctionError != nil {
					t.Fatalf("direct function failed: %s: %s", aws.ToString(out.FunctionError), out.Payload)
				}
				var actual lambdaSQSAuthorizationSends
				if e := json.Unmarshal(out.Payload, &actual); e != nil {
					t.Fatal(e)
				}
				payload := row.Result.Output["Payload"].(map[string]any)["json"]
				expected := lambdaSQSNativeInput[lambdaSQSAuthorizationSends](t, lambdaQualifiedJSON(t, payload), r.normalize())
				lambdaSQSAuthorizationAssertSends(t, r, actual, expected)
				directRequest = actual.RequestID
			}
		case row.Operation == "create_event_source_mapping":
			input := lambdaSQSNativeInput[awslambda.CreateEventSourceMappingInput](t, row.Input, r.normalize())
			var out *awslambda.CreateEventSourceMappingOutput
			out, err = r.c.lambda.CreateEventSourceMapping(t.Context(), &input)
			if row.Result.Code != "Success" {
				assertAPIError(t, err, row.Result.Code)
				continue
			}
			if err == nil {
				waiter.mapping = out
				r.replacements = append(r.replacements, row.Result.Output["UUID"].(string), aws.ToString(out.UUID))
				if out.LastProcessingResult != nil {
					t.Fatalf("successful admission invented LastProcessingResult: %q", aws.ToString(out.LastProcessingResult))
				}
				waiter.state(t, "Enabled")
			}
		case row.Operation == "send_message" && row.Phase == "source-send":
			input := lambdaSQSNativeInput[sqs.SendMessageInput](t, row.Input, r.normalize())
			var out *sqs.SendMessageOutput
			out, err = r.c.queues.SendMessage(t.Context(), &input)
			if err == nil {
				sourceID, sourceBody = aws.ToString(out.MessageId), aws.ToString(input.MessageBody)
				r.replacements = append(r.replacements, row.Result.Output["MessageId"].(string), sourceID)
			}
		default:
			continue
		}
		if err != nil {
			t.Fatalf("%s/%s: %v", row.Phase, row.Label, err)
		}
	}

	var events map[string]lambdaSQSAuthorizationEvent
	var sends map[string]lambdaSQSAuthorizationSends
	waiter.wait(t, time.Second, func() bool {
		events, sends = lambdaSQSAuthorizationLogs(t, r)
		if len(events) < len(native.Events) || len(sends) < len(native.Sends) {
			return false
		}
		if waiter.mapping != nil {
			visible, hidden := waiter.counts(t)
			return visible == 0 && hidden == 0
		}
		return true
	})
	if len(events) != len(native.Events) || len(sends) != len(native.Sends) {
		t.Fatalf("runtime attempts: events=%d sends=%d, native events=%d sends=%d", len(events), len(sends), len(native.Events), len(native.Sends))
	}
	for _, retained := range native.Events {
		expected := lambdaSQSNativeInput[lambdaSQSAuthorizationEvent](t, lambdaQualifiedJSON(t, retained.Data), r.normalize())
		requestID := directRequest
		if records, ok := expected.Event["Records"].([]any); ok {
			requestID = ""
			for id := range events {
				if id != directRequest {
					requestID = id
				}
			}
			actual := events[requestID]
			got, ok := actual.Event["Records"].([]any)
			if !ok || len(got) != len(records) || len(got) != 1 {
				t.Fatalf("source batch differs: %+v", actual)
			}
			record, want := got[0].(map[string]any), records[0].(map[string]any)
			for _, field := range []string{"messageId", "body", "eventSource", "eventSourceARN", "awsRegion", "messageAttributes"} {
				if !reflect.DeepEqual(record[field], want[field]) {
					t.Fatalf("source record %s=%v want %v", field, record[field], want[field])
				}
			}
			if record["messageId"] != sourceID || record["body"] != sourceBody || record["attributes"].(map[string]any)["ApproximateReceiveCount"] != want["attributes"].(map[string]any)["ApproximateReceiveCount"] {
				t.Fatalf("runtime record not the exact first source receive: %+v", record)
			}
		} else if !reflect.DeepEqual(events[requestID].Event, expected.Event) {
			t.Fatalf("direct runtime event=%v want %v", events[requestID].Event, expected.Event)
		}
		actual := events[requestID]
		if requestID == "" || actual.RequestID != requestID || actual.InvokedFunctionARN != r.c.functionARN || actual.InvokedFunctionARN != expected.InvokedFunctionARN {
			t.Fatalf("runtime identity differs: %+v", actual)
		}
		if requestID != directRequest {
			for _, completion := range native.Sends {
				if completion.Data.RequestID == retained.Data.RequestID {
					lambdaSQSAuthorizationAssertSends(t, r, sends[requestID], completion.Data)
				}
			}
		}
	}

	if waiter.mapping != nil {
		// All fourteen captured background reads omit this member. Read after
		// real completion, not just admission, so a synthetic success is caught.
		for _, row := range r.fixture.Observations {
			if row.Label != native.Name+"_get_event_source_mapping" || row.Phase != "background-observe" {
				continue
			}
			input := lambdaSQSNativeInput[awslambda.GetEventSourceMappingInput](t, row.Input, r.normalize())
			out, err := r.c.lambda.GetEventSourceMapping(t.Context(), &input)
			if err != nil {
				t.Fatal(err)
			}
			if out.LastProcessingResult != nil || aws.ToString(out.State) != row.Result.Output["State"] || aws.ToString(out.StateTransitionReason) != row.Result.Output["StateTransitionReason"] {
				t.Fatalf("background mapping differs from native: %+v", out)
			}
			break
		}
		if _, err := r.c.lambda.DeleteEventSourceMapping(t.Context(), &awslambda.DeleteEventSourceMappingInput{UUID: waiter.mapping.UUID}); err != nil {
			t.Fatal(err)
		}
		waiter.wait(t, 2*time.Second, func() bool {
			_, err := r.c.lambda.GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: waiter.mapping.UUID})
			if err == nil {
				return false
			}
			assertAPIError(t, err, "ResourceNotFoundException")
			return true
		})
	}
	advanceClock(t, r.clock, visibility+time.Second)
	for _, row := range r.fixture.Observations {
		if row.Label != native.Name+"_receive_message" || row.Phase != "actor-receive-after-mapping-absence" {
			continue
		}
		input := lambdaSQSNativeInput[sqs.ReceiveMessageInput](t, row.Input, r.normalize())
		// Packing the same zero-visibility message ten times is not the
		// authority contract. Recover its identity once, without a native wait.
		input.MaxNumberOfMessages, input.WaitTimeSeconds = 1, 0
		out, err := r.c.queues.ReceiveMessage(t.Context(), &input)
		if err != nil {
			t.Fatal(err)
		}
		if waiter.mapping != nil {
			if len(out.Messages) != 0 {
				t.Fatalf("acknowledged source reappeared after mapping absence: %+v", out.Messages)
			}
		} else if len(out.Messages) != 1 || aws.ToString(out.Messages[0].MessageId) != sourceID || aws.ToString(out.Messages[0].Body) != sourceBody {
			t.Fatalf("denied admission consumed or changed the exact source: %+v", out.Messages)
		}
		break
	}
}

func lambdaSQSAuthorizationLogs(t *testing.T, r *lambdaSQSControlReplay) (map[string]lambdaSQSAuthorizationEvent, map[string]lambdaSQSAuthorizationSends) {
	t.Helper()
	events := map[string]lambdaSQSAuthorizationEvent{}
	sends := map[string]lambdaSQSAuthorizationSends{}
	input := &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String("/aws/lambda/" + aws.ToString(r.c.functionName))}
	for {
		out, err := logsClient(cloudClients{r.c.server}, "test").FilterLogEvents(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range out.Events {
			message := aws.ToString(event.Message)
			if at := strings.Index(message, "AUTH_EVENT "); at >= 0 {
				var value lambdaSQSAuthorizationEvent
				if err := json.Unmarshal([]byte(strings.TrimSpace(message[at+len("AUTH_EVENT "):])), &value); err != nil {
					t.Fatal(err)
				}
				events[value.RequestID] = value
			}
			if at := strings.Index(message, "AUTH_SENDS "); at >= 0 {
				var value lambdaSQSAuthorizationSends
				if err := json.Unmarshal([]byte(strings.TrimSpace(message[at+len("AUTH_SENDS "):])), &value); err != nil {
					t.Fatal(err)
				}
				sends[value.RequestID] = value
			}
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == aws.ToString(input.NextToken) {
			return events, sends
		}
		input.NextToken = out.NextToken
	}
}

func lambdaSQSAuthorizationAssertSends(t *testing.T, r *lambdaSQSControlReplay, actual, native lambdaSQSAuthorizationSends) {
	t.Helper()
	if actual.RequestID == "" || len(actual.Sends) != len(native.Sends) {
		t.Fatalf("runtime completion differs: %+v want %+v", actual, native)
	}
	r.replacements = append(r.replacements, native.RequestID, actual.RequestID)
	expected := lambdaSQSNativeInput[lambdaSQSAuthorizationSends](t, lambdaQualifiedJSON(t, native), r.normalize())
	for i, send := range actual.Sends {
		send.Input.QueueUrl = aws.String(strings.Replace(aws.ToString(send.Input.QueueUrl), "host.docker.internal", "127.0.0.1", 1))
		want := expected.Sends[i]
		if send.Label != want.Label || send.Code != want.Code || aws.ToString(send.Input.QueueUrl) != aws.ToString(want.Input.QueueUrl) {
			t.Fatalf("function-code source context differs: got %+v want %+v", send, want)
		}
		var body, wanted map[string]any
		if err := json.Unmarshal([]byte(aws.ToString(send.Input.MessageBody)), &body); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(aws.ToString(want.Input.MessageBody)), &wanted); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(body, wanted) {
			t.Fatalf("downstream source/request identity: got %v want %v", body, wanted)
		}
		out, err := r.c.queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: send.Input.QueueUrl, MaxNumberOfMessages: 1})
		if err != nil {
			t.Fatal(err)
		}
		if send.Code != "Success" {
			if len(out.Messages) != 0 {
				t.Fatalf("denied function send reached sink: %+v", out.Messages)
			}
			continue
		}
		if len(out.Messages) != 1 || aws.ToString(out.Messages[0].MessageId) != send.Output.MessageID || aws.ToString(out.Messages[0].Body) != aws.ToString(send.Input.MessageBody) {
			t.Fatalf("sink did not contain exact runtime SDK send: %+v; send=%+v", out.Messages, send)
		}
		if _, err := r.c.queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: send.Input.QueueUrl, ReceiptHandle: out.Messages[0].ReceiptHandle}); err != nil {
			t.Fatal(err)
		}
	}
}
