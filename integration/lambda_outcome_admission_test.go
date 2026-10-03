package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/storage"
)

type lambdaAdmissionObservation struct {
	Label, Service, Operation string
	Input                     json.RawMessage
	Result                    struct {
		Code   string
		Output map[string]any
	}
}

type lambdaAdmissionCapture struct {
	Observations []lambdaAdmissionObservation
}

type lambdaAdmissionFixture struct {
	Captures map[string]lambdaAdmissionCapture
}

func lambdaAdmissionInput[T any](t *testing.T, input json.RawMessage) *T {
	t.Helper()
	var value T
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	return &value
}

// This is a control-plane replay. Native readiness polling and IAM propagation
// retries are replaced by SDK waiters; no destination publication is performed.
func TestLambdaOutcomeAdmissionNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture := lambdaFixture[lambdaAdmissionFixture](t, "outcomes_admission")
			queues := lambdaFixture[lambdaAdmissionFixture](t, "outcomes_queues")
			events := lambdaFixture[lambdaAdmissionFixture](t, "outcomes_events")
			bucket := lambdaFixture[lambdaAdmissionCapture](t, "outcomes_s3")
			source := clock.NewManual(time.Date(2026, 9, 14, 15, 0, 0, 0, time.UTC))
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "lambda-admission.sqlite"))
			}
			cloud := lambdaEventsConnect(t, backends, source)
			clients := cloudClients{cloud.server}
			root := clients.iam("test", "test", "")
			topics := admissionSNSClient(clients, "test", "us-east-1")
			buckets := s3NativeClient(clients, "test", "test")
			client := cloud.lambda
			operations := map[string]lambdaPolicyOperation{
				"create-function":                     lambdaPolicyBind(client.CreateFunction),
				"get-function-configuration":          lambdaPolicyBind(client.GetFunctionConfiguration),
				"update-function-configuration":       lambdaPolicyBind(client.UpdateFunctionConfiguration),
				"put-function-event-invoke-config":    lambdaPolicyBind(client.PutFunctionEventInvokeConfig),
				"update-function-event-invoke-config": lambdaPolicyBind(client.UpdateFunctionEventInvokeConfig),
				"get-function-event-invoke-config":    lambdaPolicyBind(client.GetFunctionEventInvokeConfig),
			}
			queueURLs := map[string]string{}
			revisions := lambdaPolicyRevisions{}
			timestamps := map[string]lambdaPolicyRevisions{}
			normalize := func(data []byte) []byte {
				// lambdaFixture decodes captures verbatim. Rebind only AWS capture
				// identities and concrete queue URLs, never handler source/ZIP bytes.
				text := strings.ReplaceAll(string(data), "000000000000", "000000000000")
				for native, local := range queueURLs {
					text = strings.ReplaceAll(text, native, local)
				}
				return []byte(text)
			}
			project := func(output map[string]any, keys ...string) map[string]any {
				result := map[string]any{}
				for _, key := range keys {
					result[key] = output[key]
				}
				return lambdaPolicyComparable(t, result)
			}
			snapshot := func(t *testing.T, name string) map[string]any {
				t.Helper()
				input := map[string]any{"FunctionName": name}
				function, err := operations["get-function-configuration"](t.Context(), input)
				if err != nil {
					t.Fatal(err)
				}
				config, err := operations["get-function-event-invoke-config"](t.Context(), input)
				if err != nil {
					assertAPIError(t, err, "ResourceNotFoundException")
				}
				// Include revision and both timestamps: failed preflight must not
				// merely restore destinations after having committed other fields.
				delete(function, "ResultMetadata")
				delete(config, "ResultMetadata")
				return map[string]any{"function": function, "config": config}
			}
			replay := func(t *testing.T, row lambdaAdmissionObservation) {
				t.Helper()
				input := normalize(row.Input)
				var err error
				switch row.Service + "/" + row.Operation {
				case "sqs/create-queue":
					var out *sqs.CreateQueueOutput
					out, err = cloud.queues.CreateQueue(t.Context(), lambdaAdmissionInput[sqs.CreateQueueInput](t, input))
					if err == nil {
						native := strings.ReplaceAll(row.Result.Output["QueueUrl"].(string), "000000000000", "000000000000")
						queueURLs[native] = aws.ToString(out.QueueUrl)
					}
				case "sqs/set-queue-attributes":
					_, err = cloud.queues.SetQueueAttributes(t.Context(), lambdaAdmissionInput[sqs.SetQueueAttributesInput](t, input))
				case "sns/create-topic":
					_, err = topics.CreateTopic(t.Context(), lambdaAdmissionInput[sns.CreateTopicInput](t, input))
				case "sns/set-topic-attributes":
					_, err = topics.SetTopicAttributes(t.Context(), lambdaAdmissionInput[sns.SetTopicAttributesInput](t, input))
				case "iam/create-role":
					_, err = root.CreateRole(t.Context(), lambdaAdmissionInput[iam.CreateRoleInput](t, input))
				case "iam/put-role-policy":
					_, err = root.PutRolePolicy(t.Context(), lambdaAdmissionInput[iam.PutRolePolicyInput](t, input))
				case "events/create-event-bus":
					_, err = cloud.events.CreateEventBus(t.Context(), lambdaAdmissionInput[eventbridge.CreateEventBusInput](t, input))
				case "events/put-rule":
					_, err = cloud.events.PutRule(t.Context(), lambdaAdmissionInput[eventbridge.PutRuleInput](t, input))
				case "s3api/create-bucket":
					_, err = buckets.CreateBucket(t.Context(), lambdaAdmissionInput[s3.CreateBucketInput](t, input))
				default:
					if row.Service != "lambda" {
						t.Fatalf("unbound admission fixture operation: %s/%s", row.Service, row.Operation)
					}
					operation, ok := operations[row.Operation]
					if !ok {
						t.Fatalf("unbound Lambda operation %s", row.Operation)
					}
					fields := *lambdaAdmissionInput[map[string]any](t, input)
					name := fields["FunctionName"].(string)
					mutates := row.Operation == "update-function-configuration" || row.Operation == "put-function-event-invoke-config" || row.Operation == "update-function-event-invoke-config"
					var before map[string]any
					if mutates {
						before = snapshot(t, name)
					}
					actual, callErr := operation(t.Context(), fields)
					if row.Result.Code != "Success" {
						assertAPIError(t, callErr, row.Result.Code)
						if mutates && !reflect.DeepEqual(before, snapshot(t, name)) {
							t.Fatal("rejected preflight changed function or event configuration")
						}
						if row.Operation == "create-function" {
							_, absentErr := client.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)})
							assertAPIError(t, absentErr, "ResourceNotFoundException")
						}
						return
					}
					if callErr != nil {
						t.Fatal(callErr)
					}
					if row.Operation == "create-function" || row.Operation == "update-function-configuration" {
						configuration := &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)}
						if row.Operation == "create-function" {
							err = awslambda.NewFunctionActiveWaiter(client, fastLambdaActiveWaiter).Wait(t.Context(), configuration, time.Minute)
						} else {
							err = awslambda.NewFunctionUpdatedWaiter(client, fastLambdaUpdatedWaiter).Wait(t.Context(), configuration, time.Minute)
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					wantData, marshalErr := json.Marshal(row.Result.Output)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					want := *lambdaAdmissionInput[map[string]any](t, normalize(wantData))
					keys := []string{"FunctionArn", "MaximumRetryAttempts", "MaximumEventAgeInSeconds", "DestinationConfig"}
					if !strings.Contains(row.Operation, "event-invoke-config") {
						keys = []string{"FunctionName", "FunctionArn", "Role", "Description", "DeadLetterConfig"}
					}
					if row.Operation == "get-function-configuration" {
						revisions.observe(t, want["RevisionId"].(string), actual["RevisionId"].(string))
					}
					if row.Operation == "get-function-configuration" || strings.Contains(row.Operation, "event-invoke-config") {
						key := name + "/function"
						if strings.Contains(row.Operation, "event-invoke-config") {
							key = name + "/event"
						}
						if timestamps[key] == nil {
							timestamps[key] = lambdaPolicyRevisions{}
						}
						if want["LastModified"] == nil || actual["LastModified"] == nil {
							t.Fatal("missing configuration timestamp")
						}
						timestamps[key].observe(t, fmt.Sprint(want["LastModified"]), fmt.Sprint(actual["LastModified"]))
					}
					if !reflect.DeepEqual(project(actual, keys...), project(want, keys...)) {
						t.Fatalf("SDK configuration=%#v; native=%#v", project(actual, keys...), project(want, keys...))
					}
					if mutates {
						after := snapshot(t, name)
						state := after["config"]
						if row.Operation == "update-function-configuration" {
							old := before["function"].(map[string]any)
							current := after["function"].(map[string]any)
							if old["RevisionId"] == current["RevisionId"] || old["LastModified"] == current["LastModified"] {
								t.Fatal("successful function patch did not advance revision and timestamp")
							}
							state = current
						} else if !reflect.DeepEqual(before["function"], after["function"]) {
							t.Fatal("event configuration update changed the function revision or configuration")
						}
						if !reflect.DeepEqual(project(state.(map[string]any), keys...), project(want, keys...)) {
							t.Fatalf("persisted configuration=%#v; native=%#v", project(state.(map[string]any), keys...), project(want, keys...))
						}
					}
				}
				if row.Result.Code == "Success" {
					if err != nil {
						t.Fatal(err)
					}
				} else {
					assertAPIError(t, err, row.Result.Code)
				}
				// Public desired configuration is immediate; effective configuration
				// follows the normal deterministic propagation delay.
				source.Advance(time.Minute)
				if _, err := cloud.cloud.RunDueJobs(t.Context(), 100); err != nil {
					t.Fatal(err)
				}
			}
			run := func(capture string, rows []lambdaAdmissionObservation, selectRow func(lambdaAdmissionObservation) bool) {
				for _, row := range rows {
					if !selectRow(row) {
						continue
					}
					if !t.Run(capture+"/"+row.Label, func(t *testing.T) { replay(t, row) }) {
						t.FailNow()
					}
				}
			}
			admissionRow := func(row lambdaAdmissionObservation) bool {
				// Failed Create already checks absence through configuration reads.
				// Repeating that check does not require package-download support.
				if row.Operation == "get-function" {
					return false
				}
				if strings.HasPrefix(row.Label, "wait-") || strings.HasPrefix(row.Label, "delete-") || strings.HasPrefix(row.Label, "absent-") {
					return false
				}
				if row.Operation == "create-topic" && lambdaAdmissionInput[sns.CreateTopicInput](t, row.Input).Attributes["FifoTopic"] == "true" {
					// Rejecting a FIFO ARN does not require implementing SNS's
					// otherwise unused FIFO data plane as test setup.
					return false
				}
				if row.Service == "lambda" {
					return true
				}
				return row.Operation == "create-queue" || row.Operation == "create-topic" || row.Operation == "create-role" || row.Operation == "put-role-policy" || row.Operation == "set-queue-attributes" || row.Operation == "set-topic-attributes"
			}
			run("admission", fixture.Captures["admission"].Observations, admissionRow)
			run("dlq_patch", fixture.Captures["patch"].Observations, admissionRow)
			run("resource_policy", fixture.Captures["resource_policy"].Observations, func(row lambdaAdmissionObservation) bool {
				// The first two creates only captured IAM propagation lag.
				return row.Label != "create-function-0" && row.Label != "create-function-1" && admissionRow(row)
			})
			queueSetup := map[string]bool{"create-audit": true, "create-dest": true, "create-no-permission": true, "create-fifo": true, "create-sns-dest": true, "create-role": true, "policy-delivery": true, "create-function-admission": true, "config-admission": true}
			inPatch := false
			run("destination_patch", queues.Captures["delivery"].Observations, func(row lambdaAdmissionObservation) bool {
				if row.Label == "admission-baseline" {
					inPatch = true
				}
				if queueSetup[row.Label] {
					return true
				}
				return inPatch && row.Service == "lambda" && (row.Operation == "update-function-configuration" || strings.Contains(row.Operation, "event-invoke-config") || strings.HasPrefix(row.Label, "dlq-state-"))
			})
			// Reapply the original destination-free Put after the patch sequence.
			// This reordered request compares configuration, not capture chronology.
			t.Run("put_replaces_destinations", func(t *testing.T) {
				for _, row := range queues.Captures["delivery"].Observations {
					if row.Label != "config-admission" {
						continue
					}
					input := lambdaAdmissionInput[awslambda.PutFunctionEventInvokeConfigInput](t, normalize(row.Input))
					out, err := client.PutFunctionEventInvokeConfig(t.Context(), input)
					if err != nil {
						t.Fatal(err)
					}
					persisted, err := client.GetFunctionEventInvokeConfig(t.Context(), &awslambda.GetFunctionEventInvokeConfigInput{FunctionName: input.FunctionName})
					if err != nil {
						t.Fatal(err)
					}
					for _, value := range []any{out, persisted} {
						data, err := json.Marshal(value)
						if err != nil {
							t.Fatal(err)
						}
						actual := *lambdaAdmissionInput[map[string]any](t, data)
						keys := []string{"MaximumRetryAttempts", "MaximumEventAgeInSeconds", "DestinationConfig"}
						if !reflect.DeepEqual(project(actual, keys...), project(row.Result.Output, keys...)) {
							t.Fatalf("replacement configuration=%#v; native=%#v", project(actual, keys...), project(row.Result.Output, keys...))
						}
					}
					source.Advance(time.Minute)
					if _, err := cloud.cloud.RunDueJobs(t.Context(), 100); err != nil {
						t.Fatal(err)
					}
					return
				}
				t.Fatal("native fixture lacks destination-free Put")
			})
			inEvents := true
			run("target_admission", events.Captures["admission"].Observations, func(row lambdaAdmissionObservation) bool {
				if row.Operation == "invoke" {
					inEvents = false
				}
				if !inEvents || strings.HasPrefix(row.Label, "ready_") {
					return false
				}
				if row.Operation == "create-function" && row.Result.Code != "Success" {
					return false
				}
				return row.Service == "lambda" || row.Operation == "create-role" || row.Operation == "put-role-policy" || row.Operation == "create-queue" || row.Operation == "create-event-bus" || row.Operation == "put-rule"
			})
			run("s3_admission", bucket.Observations, func(row lambdaAdmissionObservation) bool {
				return row.Operation == "create-bucket" || row.Operation == "create-role" || row.Operation == "put-role-policy" || row.Operation == "create-function" || strings.Contains(row.Operation, "event-invoke-config")
			})
			for _, url := range queueURLs {
				lambdaEventsQuiet(t, cloud, aws.String(url))
			}
		})
	}
}
