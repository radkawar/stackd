package stackd_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"

	"stackd"
	"stackd/internal/awstest"
	"stackd/storage"
)

type workflowLambdaObservation struct {
	awsNativeObservation
	ResponseBody struct {
		ParsedJSON json.RawMessage `json:"parsed_json"`
	} `json:"response_body"`
}

// This is an execution replay, not a substitute Lambda executor: the captured
// Python 3.12 zip, function configuration, scoped roles and ASL definition pass
// through public SDK requests and the real Docker Runtime API. SDK response
// metadata retains status, modeled headers and consistent command request IDs.
func TestStepFunctionsNativeLambdaDocker(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real Step Functions Lambda integrations")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var fixture struct {
				Account, Region string
				Observations    []workflowLambdaObservation
				Executions      map[string]struct {
					Description struct {
						Status, Input        string
						Output, Error, Cause *string
					}
					History struct{ Events []map[string]any }
				}
			}
			awsReadFixture(t, "stepfunctions/lambda_integrations.json", &fixture)
			rows := make(map[string]workflowLambdaObservation, len(fixture.Observations))
			for _, row := range fixture.Observations {
				rows[row.Label] = row
			}
			observation := func(label string) workflowLambdaObservation {
				t.Helper()
				row, ok := rows[label]
				if !ok {
					t.Fatalf("missing native Lambda observation %s", label)
				}
				return row
			}
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "workflow-lambda.sqlite"))
			}
			cloud, server := newLambdaDockerStack(t, stackd.Config{Storage: backends, AccountID: fixture.Account}, nil)
			credential := credentials.NewStaticCredentialsProvider("test", "test", "")
			functions := awslambda.New(awslambda.Options{Region: fixture.Region, BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), Credentials: credential, RetryMaxAttempts: 1})
			logs := cloudwatchlogs.New(cloudwatchlogs.Options{Region: fixture.Region, BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), Credentials: credential, RetryMaxAttempts: 1})
			wire := &awstest.WireClient{Client: server.Client()}
			workflows := sfn.New(sfn.Options{Region: fixture.Region, BaseEndpoint: aws.String(server.URL), HTTPClient: wire, Credentials: credential, RetryMaxAttempts: 1})
			clients := map[string]any{"iam": (cloudClients{server}).iam("test", "test", ""), "lambda": functions, "logs": logs, "stepfunctions": workflows}
			call := func(t *testing.T, row workflowLambdaObservation, prepare ...func(any)) any {
				t.Helper()
				out, err := awstest.CallSDK(t.Context(), clients[row.Service], row.Operation, row.Input, prepare...)
				awsNativeResult(t, row.awsNativeObservation, err)
				return out
			}
			// Register only successfully created resources, in reverse dependency
			// order. The Docker stack cleanup then disposes its owned environments.
			for _, setup := range []struct{ create, cleanup string }{
				{"create-log-group", "cleanup-delete-log-group"},
				{"create-role-lambda", "cleanup-delete-role-lambda"},
				{"put-policy-lambda", "cleanup-delete-policy-lambda"},
				{"create-role-states", "cleanup-delete-role-states"},
				{"put-policy-states", "cleanup-delete-policy-states"},
				{"create-function-1", "cleanup-delete-function"},
				{"create-machine", "cleanup-delete-machine"},
			} {
				out := call(t, observation(setup.create))
				cleanup := observation(setup.cleanup)
				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					if _, err := awstest.CallSDK(ctx, clients[cleanup.Service], cleanup.Operation, cleanup.Input); err != nil {
						t.Errorf("%s: %v", cleanup.Label, err)
					}
				})
				if created, ok := out.(*awslambda.CreateFunctionOutput); ok {
					if err := awslambda.NewFunctionActiveWaiter(functions, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: created.FunctionName}, time.Minute); err != nil {
						t.Fatal(err)
					}
				}
			}
			comparison := workflowLambdaComparison{requestIDs: map[string]string{}}
			for _, row := range fixture.Observations {
				if row.Service == "lambda" && row.Operation == "invoke" {
					t.Run(row.Label, func(t *testing.T) {
						var request struct {
							PayloadUTF8 *string `json:"PayloadUtf8"`
						}
						awsDecodeJSON(t, row.Input, &request)
						out := call(t, row, func(input any) {
							// The capture records body bytes separately, not a base64
							// SDK blob. Preserve omitted, empty, and literal null.
							if request.PayloadUTF8 != nil {
								input.(*awslambda.InvokeInput).Payload = []byte(*request.PayloadUTF8)
							}
						}).(*awslambda.InvokeOutput)
						var want struct {
							StatusCode                     int32
							FunctionError, ExecutedVersion *string
						}
						awsDecodeJSON(t, row.Result.Output, &want)
						if out.StatusCode != want.StatusCode || !reflect.DeepEqual(out.FunctionError, want.FunctionError) || !reflect.DeepEqual(out.ExecutedVersion, want.ExecutedVersion) {
							t.Fatalf("Invoke envelope = status %d, error %v, version %v; native %#v", out.StatusCode, out.FunctionError, out.ExecutedVersion, want)
						}
						comparison.json(t, "Invoke.Payload", out.Payload, row.ResponseBody.ParsedJSON)
					})
					continue
				}
				if row.Operation != "start-execution" {
					continue
				}
				name := strings.TrimPrefix(row.Label, "start-")
				t.Run(name, func(t *testing.T) {
					want, ok := fixture.Executions[name]
					if !ok {
						t.Fatalf("missing native execution %s", name)
					}
					started := call(t, row).(*sfn.StartExecutionOutput)
					ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
					defer cancel()
					var got *sfn.DescribeExecutionOutput
					for {
						if _, err := cloud.RunDueJobs(ctx, 100); err != nil {
							t.Fatal(err)
						}
						var err error
						got, err = workflows.DescribeExecution(ctx, &sfn.DescribeExecutionInput{ExecutionArn: started.ExecutionArn})
						if err != nil {
							t.Fatal(err)
						}
						if got.Status != sfntypes.ExecutionStatusRunning {
							break
						}
						select {
						case <-ctx.Done():
							t.Fatal("waiting for real Lambda workflow completion", ctx.Err())
						case <-time.After(20 * time.Millisecond):
						}
					}
					if string(got.Status) != want.Description.Status || !reflect.DeepEqual(got.Error, want.Description.Error) || (got.Output == nil) != (want.Description.Output == nil) || (got.Cause == nil) != (want.Description.Cause == nil) {
						t.Fatalf("execution outcome = %#v; native %#v", got, want.Description)
					}
					if got.StartDate == nil || got.StopDate == nil || got.StopDate.Before(*got.StartDate) {
						t.Fatalf("invalid execution timestamps: %#v", got)
					}
					comparison.json(t, "execution.input", []byte(aws.ToString(got.Input)), []byte(want.Description.Input))
					if got.Output != nil {
						comparison.json(t, "execution.output", []byte(*got.Output), []byte(*want.Description.Output))
					}
					if got.Cause != nil {
						comparison.value(t, "execution", map[string]any{"cause": *got.Cause}, map[string]any{"cause": *want.Description.Cause})
					}
					history, err := workflows.GetExecutionHistory(ctx, &sfn.GetExecutionHistoryInput{ExecutionArn: started.ExecutionArn})
					if err != nil {
						t.Fatal(err)
					}
					var document struct{ Events []map[string]any }
					awsDecodeJSON(t, wire.Body, &document)
					if history.NextToken != nil || len(document.Events) != len(want.History.Events) || len(history.Events) != len(document.Events) {
						t.Fatalf("history event sequence = %#v; native %#v", document.Events, want.History.Events)
					}
					previous := *got.StartDate
					for i, event := range history.Events {
						if event.Timestamp == nil || event.Timestamp.Before(previous) || event.Timestamp.After(*got.StopDate) {
							t.Fatalf("history event %d has invalid timestamp: %#v", i, event)
						}
						previous = *event.Timestamp
						actual, expected := document.Events[i], maps.Clone(want.History.Events[i])
						delete(actual, "timestamp")
						delete(expected, "timestamp")
						comparison.value(t, "history", actual, expected)
					}
				})
			}
			// An Event acknowledgement alone does not prove handler execution.
			// Check the two retained asynchronous handler log payloads, without
			// asserting native collection latency or cross-invocation ordering.
			row := observation("event-delivery-logs-0")
			var native struct{ Events []struct{ Message string } }
			awsDecodeJSON(t, row.Result.Output, &native)
			wantMessages := map[string]bool{}
			var invalidInput struct{ Payload string }
			awsDecodeJSON(t, []byte(fixture.Executions["sdk-payload-base64-string"].Description.Input), &invalidInput)
			decoded, err := base64.StdEncoding.DecodeString(invalidInput.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var invalidEvent struct{ Marker string }
			awsDecodeJSON(t, decoded, &invalidEvent)
			if invalidEvent.Marker == "" || invalidInput.Payload == "" {
				t.Fatal("native invalid-payload probe has no identifiable handler side effect")
			}
			invalidDelivery := func(message string) bool {
				return strings.HasPrefix(message, "PROBE_EVENT ") && (strings.Contains(message, invalidEvent.Marker) || strings.Contains(message, invalidInput.Payload))
			}
			for _, event := range native.Events {
				if invalidDelivery(event.Message) {
					t.Fatal("native malformed payload unexpectedly reached the handler", event.Message)
				}
				if strings.HasPrefix(event.Message, "PROBE_EVENT ") && strings.Contains(event.Message, "event-delivery") {
					wantMessages[strings.TrimSpace(event.Message)] = true
				}
			}
			if len(wantMessages) != 2 {
				t.Fatal("native fixture does not retain both Event deliveries", wantMessages)
			}
			var logInput cloudwatchlogs.FilterLogEventsInput
			awsDecodeJSON(t, row.Input, &logInput)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			for {
				if _, err := cloud.RunDueJobs(ctx, 100); err != nil {
					t.Fatal(err)
				}
				seen := map[string]bool{}
				pages := cloudwatchlogs.NewFilterLogEventsPaginator(logs, &logInput)
				for pages.HasMorePages() {
					page, err := pages.NextPage(ctx)
					if err != nil {
						t.Fatal(err)
					}
					for _, event := range page.Events {
						message := strings.TrimSpace(aws.ToString(event.Message))
						// This is a bounded observation matching the retained native
						// log window, not an unbounded absence/latency guarantee.
						if invalidDelivery(message) {
							t.Fatal("malformed SDK payload reached the real handler", message)
						}
						if wantMessages[message] {
							seen[message] = true
						}
					}
				}
				if reflect.DeepEqual(seen, wantMessages) {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("waiting for real asynchronous Lambda handler logs", seen, ctx.Err())
				case <-time.After(20 * time.Millisecond):
				}
			}
		})
	}
}

type workflowLambdaComparison struct {
	requestIDs map[string]string
}

func (c workflowLambdaComparison) json(t *testing.T, path string, got, want []byte) {
	t.Helper()
	var actual, expected any
	awsDecodeJSON(t, got, &actual)
	awsDecodeJSON(t, want, &expected)
	c.value(t, path, actual, expected)
}

func (c workflowLambdaComparison) value(t *testing.T, path string, got, want any) {
	t.Helper()
	switch expected := want.(type) {
	case map[string]any:
		actual, ok := got.(map[string]any)
		stepFunctionsNormalizeMetadata(t, path+".native", expected)
		if ok {
			stepFunctionsNormalizeMetadata(t, path+".local", actual)
		}
		if metadata, present := expected["SdkResponseMetadata"].(map[string]any); present {
			localMetadata, _ := actual["SdkResponseMetadata"].(map[string]any)
			c.bindRequestID(t, path, localMetadata["RequestId"], metadata["RequestId"])
		}
		if !ok || len(actual) != len(expected) {
			t.Fatalf("%s: got %#v, native %#v", path, got, want)
		}
		for key, value := range expected {
			observed, present := actual[key]
			if !present {
				t.Fatalf("%s: missing native field %s", path, key)
			}
			if key == "requestId" {
				c.bindRequestID(t, path, observed, value)
				continue
			}
			if key == "cause" {
				nativeText, nativeOK := value.(string)
				actualText, actualOK := observed.(string)
				if nativeOK && !json.Valid([]byte(nativeText)) {
					// Lambda's provider-specific parser diagnostic is not stable.
					// Its FAILED state/error class and absence of handler effects
					// are asserted separately from this nonempty diagnostic.
					if !actualOK || actualText == "" {
						t.Fatalf("%s.cause: missing service diagnostic", path)
					}
					continue
				}
			}
			// JSON-bearing strings remain strings at the public boundary. Decode
			// only after checking their kind, so SDK Payload text cannot silently
			// become optimized Payload objects (or Event empty text become null).
			if text, ok := value.(string); ok && (key == "Payload" || key == "input" || key == "output" || key == "parameters" || key == "cause") && json.Valid([]byte(text)) {
				actualText, ok := observed.(string)
				if !ok {
					t.Fatalf("%s.%s: got %T, native JSON text", path, key, observed)
				}
				c.json(t, path+"."+key, []byte(actualText), []byte(text))
				continue
			}
			c.value(t, path+"."+key, observed, value)
		}
	case []any:
		actual, ok := got.([]any)
		if !ok || len(actual) != len(expected) {
			t.Fatalf("%s: got %#v, native %#v", path, got, want)
		}
		for i := range expected {
			c.value(t, path, actual[i], expected[i])
		}
	default:
		if nativeID, ok := want.(string); ok {
			if bound, exists := c.requestIDs[nativeID]; exists {
				if got != bound {
					t.Fatalf("%s: request ID = %#v, bound %s", path, got, bound)
				}
				return
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: got %#v, native %#v", path, got, want)
		}
	}
}

func (c workflowLambdaComparison) bindRequestID(t *testing.T, path string, got, want any) {
	t.Helper()
	nativeID, nativeOK := want.(string)
	id, localOK := got.(string)
	if !nativeOK || !localOK || nativeID == "" || id == "" {
		t.Fatalf("%s: invalid request IDs: got %#v, native %#v", path, got, want)
	}
	if bound, exists := c.requestIDs[nativeID]; exists && bound != id {
		t.Fatalf("%s: request ID changed from %s to %s", path, bound, id)
	}
	for other, bound := range c.requestIDs {
		if other != nativeID && bound == id {
			t.Fatalf("%s: distinct requests reused request ID %s", path, id)
		}
	}
	c.requestIDs[nativeID] = id
}
