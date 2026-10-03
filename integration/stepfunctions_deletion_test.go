package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	sfnstore "stackd/storage/stepfunctions"
)

// Hold discovery of physical cleanup only, using the same service-owned work
// records and scheduler as production. This lets public SDK reads observe the
// committed terminal history without requiring an AWS worker/polling delay or
// changing the captured machines' OFF logging configuration. Admission,
// callbacks, transitions, history, events and eventual removal remain real.
// The gate is not armed until active-deletion checks and recovery have passed.
type stepFunctionsDeletionDiscovery struct {
	sfnstore.Repository
	hold *atomic.Bool
}

type stepFunctionsDeletionReader struct {
	sfnstore.Reader
	hold *atomic.Bool
}

func (r *stepFunctionsDeletionDiscovery) View(ctx context.Context, fn func(sfnstore.Reader) error) error {
	return r.Repository.View(ctx, func(reader sfnstore.Reader) error {
		return fn(stepFunctionsDeletionReader{Reader: reader, hold: r.hold})
	})
}

func (r stepFunctionsDeletionReader) NextWork() (sfnstore.WorkRecord, error) {
	work, err := r.Reader.NextWork()
	if err == nil && work.Kind == sfnstore.WorkMachineDelete && r.hold.Load() {
		return sfnstore.WorkRecord{}, sfnstore.ErrNotFound
	}
	return work, err
}

func TestStepFunctionsNativeDeletionSDK(t *testing.T) {
	var fixture struct {
		Account   string `json:"caller_account"`
		Region    string
		StartedAt string `json:"started_at"`
		Bounds    struct {
			WaitSeconds int `json:"wait_seconds"`
		}
		Observations []struct {
			awsNativeObservation
			Request json.RawMessage
		}
		TerminalResults map[string]struct {
			Status, Error, Cause string
			HistoryObservation   string `json:"history_observation"`
			EventObservation     string `json:"event_receive_observation"`
		} `json:"terminal_results"`
	}
	awsReadFixture(t, "stepfunctions/deletion_lifecycle.json", &fixture)
	row := func(label string) awsNativeObservation {
		t.Helper()
		for _, observation := range fixture.Observations {
			if observation.Label == label {
				result := observation.awsNativeObservation
				result.Input = observation.Request
				return result
			}
		}
		t.Fatalf("missing native deletion observation %q", label)
		return awsNativeObservation{}
	}
	start, err := time.Parse(time.RFC3339Nano, fixture.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := &stepFunctionsReplayClock{Manual: clock.NewManual(start), timers: make(chan time.Time, 256)}
			var holdCleanup atomic.Bool
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				repository := config.Storage.StepFunctions
				if previous, ok := repository.(*stepFunctionsDeletionDiscovery); ok {
					repository = previous.Repository
				}
				config.Storage.StepFunctions = &stepFunctionsDeletionDiscovery{Repository: repository, hold: &holdCleanup}
				return startPublicCloud(t, config)
			})
			r := &stepFunctionsNativeReplay{clients: clients, reopen: reopen, clock: source,
				fixture:  stepFunctionsNativeFixture{Account: fixture.Account, Region: fixture.Region},
				bindings: map[string]string{}, timestamps: map[string]string{}}
			call := func(label string, prepare ...func(any)) any {
				t.Helper()
				observation := row(label)
				t.Logf("native deletion observation: %s", label)
				wire := &awstest.WireClient{Client: r.clients.server.Client()}
				config := aws.Config{Region: fixture.Region, HTTPClient: wire, RetryMaxAttempts: 1,
					Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")}
				endpoint := aws.String(r.clients.server.URL)
				var client any
				switch observation.Service {
				case "iam":
					client = iam.NewFromConfig(config, func(o *iam.Options) { o.BaseEndpoint = endpoint })
				case "events":
					client = eventbridge.NewFromConfig(config, func(o *eventbridge.Options) { o.BaseEndpoint = endpoint })
				case "sqs":
					client = sqs.NewFromConfig(config, func(o *sqs.Options) { o.BaseEndpoint = endpoint })
				case "stepfunctions":
					client = sfn.NewFromConfig(config, func(o *sfn.Options) { o.BaseEndpoint = endpoint })
				default:
					t.Fatalf("unmapped deletion fixture service %q", observation.Service)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				output, err := awstest.CallSDK(ctx, client, observation.Operation, r.input(t, observation.Input), prepare...)
				awsNativeResult(t, observation, err)
				if err != nil {
					return nil
				}
				switch actual := output.(type) {
				case *iam.CreateRoleOutput:
					var native struct {
						Role struct {
							Arn                      string
							AssumeRolePolicyDocument map[string]any
						}
					}
					awsDecodeJSON(t, observation.Result.Output, &native)
					if actual.Role == nil || aws.ToString(actual.Role.Arn) != native.Role.Arn {
						t.Fatalf("owned role identity differs: %+v", actual)
					}
					policy, err := url.QueryUnescape(aws.ToString(actual.Role.AssumeRolePolicyDocument))
					if err != nil {
						t.Fatal(err)
					}
					var trust map[string]any
					awsDecodeJSON(t, []byte(policy), &trust)
					r.compare(t, ".trust(JSON)", native.Role.AssumeRolePolicyDocument, trust)
					return output
				case *sqs.CreateQueueOutput:
					var native sqs.CreateQueueOutput
					if err := awstest.DecodeSDK(observation.Result.Output, &native); err != nil {
						t.Fatal(err)
					}
					r.bind(t, r.bindings, aws.ToString(native.QueueUrl), aws.ToString(actual.QueueUrl), true)
					return output
				case *sqs.ReceiveMessageOutput:
					// Native batches and long-poll latency are not a delivery contract.
					// Every actual envelope and acknowledgement is checked below.
					return output
				case *sfn.SendTaskSuccessOutput:
					var body map[string]any
					awsDecodeJSON(t, wire.Body, &body)
					if wire.Status != 200 || body == nil || len(body) != 0 {
						t.Fatalf("valid retained callback was not acknowledged with native empty success: HTTP %d %s", wire.Status, wire.Body)
					}
				}
				native := reflect.New(reflect.TypeOf(output).Elem()).Interface()
				if err := awstest.DecodeSDK(observation.Result.Output, native); err != nil {
					t.Fatal(err)
				}
				if actual, ok := output.(*sfn.GetExecutionHistoryOutput); ok {
					expected := native.(*sfn.GetExecutionHistoryOutput)
					for _, history := range []*sfn.GetExecutionHistoryOutput{expected, actual} {
						var previous time.Time
						for i := range history.Events {
							event := &history.Events[i]
							if event.Timestamp == nil || event.Timestamp.Before(previous) || history == actual && event.Timestamp.After(source.Now()) {
								t.Fatalf("invalid %s history timestamp: %+v", label, event)
							}
							previous = *event.Timestamp
							event.Timestamp = nil // Preserve all IDs, predecessors, event kinds and data, not provider latency.
						}
					}
					if len(actual.Events) == len(expected.Events) {
						for i, event := range expected.Events {
							if failure := event.ExecutionFailedEventDetails; failure != nil {
								got := actual.Events[i].ExecutionFailedEventDetails
								if got == nil || aws.ToString(got.Error) != aws.ToString(failure.Error) || aws.ToString(got.Cause) != aws.ToString(failure.Cause) {
									t.Fatalf("%s lost exact native deletion failure: %+v", label, got)
								}
							}
						}
					}
				}
				if actual, ok := output.(*sfn.DescribeExecutionOutput); ok {
					expected := native.(*sfn.DescribeExecutionOutput)
					if aws.ToString(actual.Cause) != aws.ToString(expected.Cause) {
						t.Fatalf("%s cause = %q, native %q", label, aws.ToString(actual.Cause), aws.ToString(expected.Cause))
					}
				}
				r.compare(t, "."+label, stepFunctionsSDKObject(t, native), stepFunctionsSDKObject(t, output))
				return output
			}
			for _, label := range []string{
				"create-role", "role-inline-policies-empty", "role-attached-policies-empty", "create-queue", "create-rule",
				"queue-owned-rule-policy", "rule-owned-queue-target", "rule-visible", "rule-target-visible",
				"create-activity", "create-wait-machine", "create-activity-machine", "activity-start",
			} {
				call(label)
			}
			r.drain(t)
			call("activity-lease-before-delete") // Binds the redacted token to this real retained lease.
			call("wait-start")
			r.drain(t)
			for _, kind := range []string{"wait", "activity"} {
				for _, resource := range []string{"machine", "execution", "history"} {
					call("before-delete-" + kind + "-" + resource)
				}
			}
			call("delete-wait-while-active")
			call("delete-activity-while-active")
			checkActiveDeletion := func() {
				t.Helper()
				r.drain(t) // Cleanup is unheld: premature removal/abort must fail these reads.
				for _, kind := range []string{"wait", "activity"} {
					for _, resource := range []string{"machine", "execution", "history", "new-start"} {
						call("immediate-after-delete-" + kind + "-" + resource)
					}
				}
			}
			checkActiveDeletion()
			r.clients = reopen()
			checkActiveDeletion() // SQLite must retain both DELETING intent and the running activity lease.
			var queueRequest sqs.CreateQueueInput
			if err := awstest.DecodeSDK(row("create-queue").Input, &queueRequest); err != nil {
				t.Fatal(err)
			}
			queues := sqs.New(sqs.Options{Region: fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1,
				Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")})
			queue, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: queueRequest.QueueName})
			if err != nil {
				t.Fatal(err)
			}
			var nativeQueue sqs.CreateQueueOutput
			if err := awstest.DecodeSDK(row("create-queue").Result.Output, &nativeQueue); err != nil {
				t.Fatal(err)
			}
			r.bindings[aws.ToString(nativeQueue.QueueUrl)] = aws.ToString(queue.QueueUrl)

			// Index real captured envelopes by execution/status, not native SQS
			// batch position. Redacted receipts are rebound before the captured ack.
			type capturedEvent struct {
				envelope map[string]any
				receipt  string
				ack      string
			}
			nativeEvents := map[string]capturedEvent{}
			for _, label := range []string{"events-receive-0", "events-receive-1", "events-receive-3"} {
				var received sqs.ReceiveMessageOutput
				if err := awstest.DecodeSDK(row(label).Result.Output, &received); err != nil {
					t.Fatal(err)
				}
				for i, message := range received.Messages {
					var envelope map[string]any
					awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &envelope)
					detail := envelope["detail"].(map[string]any)
					key := fmt.Sprint(detail["executionArn"], "/", detail["status"])
					nativeEvents[key] = capturedEvent{envelope: envelope, receipt: aws.ToString(message.ReceiptHandle), ack: fmt.Sprintf("events-ack-%s-%d", strings.TrimPrefix(label, "events-receive-"), i)}
				}
			}
			seenEvents := map[string]bool{}
			terminal := map[string]*sfn.DescribeExecutionOutput{}
			consume := func(label string) {
				t.Helper()
				r.drain(t)
				for range 8 {
					received := call(label, func(input any) { input.(*sqs.ReceiveMessageInput).WaitTimeSeconds = 0 }).(*sqs.ReceiveMessageOutput)
					if len(received.Messages) == 0 {
						return
					}
					for _, message := range received.Messages {
						var actual map[string]any
						awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &actual)
						detail, ok := actual["detail"].(map[string]any)
						if !ok {
							t.Fatalf("not a native workflow status envelope: %s", aws.ToString(message.Body))
						}
						key := fmt.Sprint(detail["executionArn"], "/", detail["status"])
						expected, ok := nativeEvents[key]
						if !ok {
							t.Fatalf("unexpected workflow event (including an abort/success): %s", aws.ToString(message.Body))
						}
						if id, _ := actual["id"].(string); !stepFunctionsContextUUID.MatchString(id) {
							t.Fatalf("missing generated EventBridge event identity: %s", aws.ToString(message.Body))
						}
						at, err := time.Parse(time.RFC3339Nano, fmt.Sprint(actual["time"]))
						if err != nil || at.After(source.Now()) || at.Before(start.Truncate(time.Second)) || detail["startDate"] != float64(start.UnixMilli()) {
							t.Fatalf("event lost actual execution time: %s", aws.ToString(message.Body))
						}
						if detail["status"] == "FAILED" {
							execution := terminal[fmt.Sprint(detail["executionArn"])]
							if execution == nil || execution.StopDate == nil || detail["stopDate"] != float64(execution.StopDate.UnixMilli()) {
								t.Fatalf("terminal event preceded completion or lost stop time: %s", aws.ToString(message.Body))
							}
						}
						// Only generated identities and service/provider instants differ.
						// Lowercase native event keys retain exact error, cause and nulls.
						for _, envelope := range []map[string]any{expected.envelope, actual} {
							delete(envelope, "id")
							delete(envelope, "time")
							data := envelope["detail"].(map[string]any)
							delete(data, "startDate")
							delete(data, "stopDate")
						}
						r.compare(t, ".event(JSON)", expected.envelope, actual)
						seenEvents[key] = true
						r.bindings[expected.receipt] = aws.ToString(message.ReceiptHandle)
						call(expected.ack)
					}
				}
				t.Fatal("workflow status queue did not settle")
			}
			for _, kind := range []string{"activity", "wait"} {
				expected, ok := fixture.TerminalResults[kind]
				if !ok || expected.Status != "FAILED" || expected.Error != "States.Runtime" {
					t.Fatalf("missing native deletion terminal contract for %s", kind)
				}
				holdCleanup.Store(true)
				if kind == "activity" {
					call("activity-callback-after-delete")
				} else {
					advanceClock(t, source.Manual, time.Duration(fixture.Bounds.WaitSeconds)*time.Second)
				}
				r.drain(t)
				call(expected.HistoryObservation) // Exact sequence forbids WaitStateExited, ActivitySucceeded and Pass events.
				execution := call(strings.TrimSuffix(expected.HistoryObservation, "history") + "execution").(*sfn.DescribeExecutionOutput)
				if string(execution.Status) != expected.Status || aws.ToString(execution.Error) != expected.Error || aws.ToString(execution.Cause) != expected.Cause {
					t.Fatalf("%s did not fail at its next transition: %+v", kind, execution)
				}
				terminal[aws.ToString(execution.ExecutionArn)] = execution
				holdCleanup.Store(false)
				r.drain(t)
				// Inspect retained downstream effects after physical machine/history
				// removal; no provider polling interval is part of this assertion.
				consume(expected.EventObservation)
				if !seenEvents[aws.ToString(execution.ExecutionArn)+"/FAILED"] {
					t.Fatalf("%s terminal EventBridge event did not reach the real SQS target", kind)
				}
				absence := "poll-13-activity-"
				if kind == "wait" {
					absence = "poll-9-wait-"
				}
				for _, resource := range []string{"machine", "execution", "history"} {
					call(absence + resource)
				}
				if kind == "activity" {
					for _, resource := range []string{"machine", "execution", "history"} {
						call("after-callback-wait-" + resource)
					}
				}
			}
			for key := range nativeEvents {
				if !seenEvents[key] {
					t.Fatalf("captured execution status never reached the actual queue: %s", key)
				}
			}
		})
	}
}
