package stackd_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type alarmDeliveryCall struct {
	Label, Service, Operation string
	Input                     json.RawMessage
}

type alarmDeliveryDocument struct {
	Document map[string]any
}

type alarmDeliveryStep struct {
	Label                     string
	Call                      *alarmDeliveryCall
	AdvanceMS                 int64 `json:"advance_ms"`
	Events, Payloads, History []int
}

type alarmDeliveryScenario struct {
	Name                      string
	AlarmName                 string            `json:"alarm_name"`
	AlarmType                 cwtypes.AlarmType `json:"alarm_type"`
	LogPrefix                 string            `json:"log_prefix"`
	Setup                     []alarmDeliveryCall
	Steps                     []alarmDeliveryStep
	Events, Payloads, History []alarmDeliveryDocument
}

// This replay uses actual EventBridge -> SQS delivery and Python stdout from
// the Docker Lambda runtime. Native collection windows are not latency SLAs;
// only the service clock controls alarm deadlines, never container wall time.
func TestCloudWatchNativeAlarmDeliveryDocker(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real CloudWatch alarm Lambda delivery")
	}
	fixture := lambdaFixture[struct {
		Account   string
		Scenarios []alarmDeliveryScenario
	}](t, "../cloudwatch/alarm_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Scenarios {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				backends := storage.NewMemory()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "alarm-delivery.sqlite"))
				}
				source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
				c := lambdaEventsConnect(t, backends, source)
				clients := cloudClients{c.server}
				root := clients.iam("test", "test", "")
				logs := logsClient(clients, "test")
				alarms := metricsClient(clients, "test")
				var roleInput iam.CreateRoleInput
				if err := json.Unmarshal(scenario.Setup[0].Input, &roleInput); err != nil {
					t.Fatal(err)
				}
				role, err := root.CreateRole(t.Context(), &roleInput)
				if err != nil {
					t.Fatal(err)
				}
				// The shared Docker constructor uses its default account. Keep the
				// native fixture's normalized account and translate only at replay.
				account := strings.Split(aws.ToString(role.Role.Arn), ":")[4]
				encoded, err := json.Marshal(scenario)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(bytes.ReplaceAll(encoded, []byte(fixture.Account), []byte(account)), &scenario); err != nil {
					t.Fatal(err)
				}
				invoke := func(call alarmDeliveryCall) {
					t.Helper()
					client := map[string]any{"iam": root, "logs": logs, "lambda": c.lambda, "events": c.events, "sqs": c.queues, "cloudwatch": alarms}[call.Service]
					operation := ""
					for _, word := range strings.Split(call.Operation, "-") {
						operation += strings.ToUpper(word[:1]) + word[1:]
					}
					out, err := awstest.CallSDK(t.Context(), client, operation, call.Input, func(input any) {
						switch input := input.(type) {
						case *sqs.SetQueueAttributesInput:
							input.QueueUrl = c.outputURL
						case *awslambda.CreateFunctionInput:
							// The captured zip is the real, tiny logging handler. Only
							// the runtime version changes to the installed Docker image.
							input.Runtime = lambdatypes.RuntimePython312
							input.Role = role.Role.Arn
							c.functionName = input.FunctionName
						}
					})
					if err != nil {
						t.Fatalf("%s: %v", call.Label, err)
					}
					switch out := out.(type) {
					case *sqs.CreateQueueOutput:
						c.outputURL = out.QueueUrl
					case *awslambda.CreateFunctionOutput:
						c.functionARN = aws.ToString(out.FunctionArn)
						if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: c.functionName}, time.Minute); err != nil {
							t.Fatal(err)
						}
					}
				}
				for _, call := range scenario.Setup[1:] {
					invoke(call)
				}
				comparison := alarmDeliveryComparison{times: alarmControlTimes{}}
				for index, step := range scenario.Steps {
					label := step.Label
					if step.Call != nil {
						label = step.Call.Label
						if err := source.Advance(time.Millisecond); err != nil {
							t.Fatal(err)
						}
						invoke(*step.Call)
					}
					if err := source.Advance(time.Duration(step.AdvanceMS) * time.Millisecond); err != nil {
						t.Fatal(err)
					}
					t.Logf("native replay step %d: %s", index, label)
					if _, err := c.cloud.RunDueJobs(t.Context(), 100); err != nil {
						t.Fatal(err)
					}
					if len(step.Events) != 0 {
						messages := lambdaEventsReceive(t, c, c.outputURL, len(step.Events))
						for i, message := range messages {
							var event map[string]any
							if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &event); err != nil {
								t.Fatal(err)
							}
							comparison.compare(t, "event", event, scenario.Events[step.Events[i]].Document)
						}
					}
					// Poll actual handler logs and public action history, not an
					// internal invocation status or a replacement invoker.
					deadline := time.Now().Add(time.Minute)
					for {
						if _, err := c.cloud.RunDueJobs(t.Context(), 100); err != nil {
							t.Fatal(err)
						}
						payloads := alarmDeliveryLogs(t, logs, "/aws/lambda/"+aws.ToString(c.functionName), scenario.LogPrefix)
						history := alarmDeliveryHistory(t, alarms, scenario)
						if len(payloads) > len(step.Payloads) || len(history) > len(step.History) {
							t.Fatalf("%s unexpected consumer effects: payloads %v, action history %v", label, payloads, history)
						}
						if len(payloads) == len(step.Payloads) && len(history) == len(step.History) {
							break
						}
						if time.Now().After(deadline) {
							t.Fatalf("%s waiting for native consumer effects: payloads %v, action history %v", label, payloads, history)
						}
						time.Sleep(20 * time.Millisecond)
					}
					// A bounded local absence observation, deliberately not an AWS
					// exactly-once or arbitrarily-delayed-delivery guarantee.
					lambdaEventsQuiet(t, c, c.outputURL)
					payloads := alarmDeliveryLogs(t, logs, "/aws/lambda/"+aws.ToString(c.functionName), scenario.LogPrefix)
					history := alarmDeliveryHistory(t, alarms, scenario)
					if len(payloads) != len(step.Payloads) || len(history) != len(step.History) {
						t.Fatalf("%s unexpected delayed action: payloads %v, history %v", label, payloads, history)
					}
					for i, expected := range step.Payloads {
						comparison.compare(t, "lambda", payloads[i], scenario.Payloads[expected].Document)
					}
					for i, expected := range step.History {
						comparison.compare(t, "history", history[i], scenario.History[expected].Document)
					}
				}
			})
		}
	}
}

func alarmDeliveryLogs(t *testing.T, client *cloudwatchlogs.Client, group, prefix string) []map[string]any {
	t.Helper()
	var payloads []map[string]any
	var token *string
	seen := map[string]bool{}
	for {
		out, err := client.FilterLogEvents(t.Context(), &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String(group), NextToken: token})
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range out.Events {
			message := aws.ToString(event.Message)
			if !strings.HasPrefix(message, prefix) || seen[aws.ToString(event.EventId)] {
				continue
			}
			seen[aws.ToString(event.EventId)] = true
			var payload map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(message, prefix)), &payload); err != nil {
				t.Fatalf("real handler payload: %v: %s", err, message)
			}
			payloads = append(payloads, payload)
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == aws.ToString(token) {
			return payloads
		}
		token = out.NextToken
	}
}

func alarmDeliveryHistory(t *testing.T, client *cloudwatch.Client, scenario alarmDeliveryScenario) []map[string]any {
	t.Helper()
	out, err := client.DescribeAlarmHistory(t.Context(), &cloudwatch.DescribeAlarmHistoryInput{
		AlarmName: aws.String(scenario.AlarmName), AlarmTypes: []cwtypes.AlarmType{scenario.AlarmType},
		HistoryItemType: cwtypes.HistoryItemTypeAction, ScanBy: cwtypes.ScanByTimestampAscending, MaxRecords: aws.Int32(100),
	})
	if err != nil {
		t.Fatal(err)
	}
	var history []map[string]any
	for _, item := range out.AlarmHistoryItems {
		var data map[string]any
		if err := json.Unmarshal([]byte(aws.ToString(item.HistoryData)), &data); err != nil {
			t.Fatal(err)
		}
		history = append(history, data)
	}
	return history
}

type alarmDeliveryComparison struct {
	times alarmControlTimes
}

func (c *alarmDeliveryComparison) compare(t *testing.T, path string, got, want any) {
	t.Helper()
	if expected, ok := want.(map[string]any); ok {
		actual, ok := got.(map[string]any)
		if !ok || len(actual) != len(expected) {
			t.Fatalf("%s fields: local %v; native %v", path, got, want)
		}
		if arn, ok := expected["arn"].(string); ok {
			path += "/" + arn
		}
		if strings.HasSuffix(path, "lambda") {
			data, ok := actual["alarmData"].(map[string]any)
			if !ok {
				t.Fatalf("Lambda alarmData is not an object: %v", actual)
			}
			state, ok := data["state"].(map[string]any)
			if !ok || !nativeAlarmEvaluationTime(t, fmt.Sprint(actual["time"])).Equal(nativeAlarmEvaluationTime(t, fmt.Sprint(state["timestamp"]))) {
				t.Fatalf("Lambda release time does not identify delivered state: %v", actual)
			}
		}
		for key, value := range expected {
			other, exists := actual[key]
			if !exists {
				t.Fatalf("%s missing native field %s", path, key)
			}
			field := key
			// State timestamps retain relationships across previous/current
			// documents and across EventBridge and real Lambda consumers.
			if key == "previousState" {
				field = "state"
			}
			if key == "previousConfiguration" {
				field = "configuration"
			}
			childPath := path + "/" + field
			if key == "reasonData" {
				actualText, actualOK := other.(string)
				expectedText, expectedOK := value.(string)
				if !actualOK || !expectedOK {
					t.Fatalf("%s reasonData must remain JSON text: %v", path, other)
				}
				c.compare(t, childPath, nativeAlarmEvaluationReason(t, json.RawMessage(actualText)), nativeAlarmEvaluationReason(t, json.RawMessage(expectedText)))
				continue
			}
			if key == "id" {
				actualID, ok := other.(string)
				if !ok || actualID == "" {
					t.Fatalf("%s missing opaque ID", path)
				}
				continue
			}
			if key == "timestamp" || key == "stateUpdateTimestamp" {
				localTime, nativeTime := fmt.Sprint(other), fmt.Sprint(value)
				if key == "stateUpdateTimestamp" {
					localMS, ok := other.(float64)
					nativeMS, nativeOK := value.(float64)
					if !ok || !nativeOK {
						t.Fatalf("action timestamp is not epoch milliseconds: %v", other)
					}
					localTime = time.UnixMilli(int64(localMS)).UTC().Format(time.RFC3339Nano)
					nativeTime = time.UnixMilli(int64(nativeMS)).UTC().Format(time.RFC3339Nano)
				} else {
					localTime = nativeAlarmEvaluationTime(t, localTime).Format(time.RFC3339Nano)
					nativeTime = nativeAlarmEvaluationTime(t, nativeTime).Format(time.RFC3339Nano)
				}
				// Event envelopes intentionally have second precision. State and
				// configuration domains keep millisecond equality/order instead.
				domain := strings.ReplaceAll(path, "lambda/alarmData", "event/detail")
				c.times.compare(t, domain+"/"+field+"Timestamp", localTime, nativeTime)
				continue
			}
			if key == "time" {
				if nativeAlarmEvaluationTime(t, fmt.Sprint(other)).IsZero() {
					t.Fatalf("%s invalid event time", path)
				}
				continue
			}
			computed := key == "actionsSuppressedReason" || key == "error" && value != nil
			if key == "reason" {
				text, _ := value.(string)
				computed = strings.HasPrefix(text, "arn:") || strings.HasPrefix(text, "Unchecked:")
			}
			if computed {
				if text, ok := other.(string); !ok || text == "" {
					t.Fatalf("%s missing explanatory text for %s", path, key)
				}
				continue
			}
			c.compare(t, childPath, other, value)
		}
		return
	}
	if expected, ok := want.([]any); ok {
		actual, ok := got.([]any)
		if !ok || len(actual) != len(expected) {
			t.Fatalf("%s collection: local %v; native %v", path, got, want)
		}
		for i := range expected {
			c.compare(t, path, actual[i], expected[i])
		}
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: local %#v; native %#v", path, got, want)
	}
}
