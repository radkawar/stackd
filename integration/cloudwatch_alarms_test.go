package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/transport/http/protocol/awsquery"

	"stackd"
	"stackd/internal/awstest"
)

type nativeAlarmControlFixture struct {
	nativeMetricFixture
	Region      string
	Protocols   []string
	Limitations []string
	Scenarios   []struct {
		Name, Limitation string
		Steps            []struct {
			Label, Compare, Retains       string
			At                            string
			HistorySince                  int64 `json:"history_since_ms"`
			AdvanceSeconds                int   `json:"advance_seconds"`
			UpdatedAfterTransitionSeconds int   `json:"updated_after_transition_seconds"`
		}
	}
}

// Requests advance one millisecond; fixture steps explicitly advance service
// time when evaluation is part of the workflow. These ticks are not an AWS
// processing-latency oracle. Native fixtures own the observable comparisons.
func TestCloudWatchNativeAlarmControls(t *testing.T) {
	for _, filename := range []string{"alarm_controls", "alarm_composites", "alarm_namespaces", "metric_insights_contributor_lifetime", "metric_insights_contributor_actions", "metric_insights_contributor_samples", "metric_insights_contributor_conversion"} {
		t.Run(filename, func(t *testing.T) {
			data, err := os.ReadFile("../testdata/aws/cloudwatch/" + filename + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var fixture nativeAlarmControlFixture
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			for _, limitation := range fixture.Limitations {
				t.Log(limitation)
			}
			protocols := fixture.Protocols
			if len(protocols) == 0 {
				protocols = []string{"rpc"}
			}
			for _, protocol := range protocols {
				for _, backend := range []string{"memory", "sqlite"} {
					for _, scenario := range fixture.Scenarios {
						t.Run(backend+"/"+scenario.Name+"/"+protocol, func(t *testing.T) {
							t.Log(scenario.Limitation)
							cloud, source := metricFixtureCloud(t, backend, fixture.nativeMetricFixture)
							client := metricsClient(cloud, "test")
							options := client.Options()
							if fixture.Region != "" {
								options.Region = fixture.Region
							}
							if protocol == "query" {
								options.Protocol = awsquery.New(&smithy.ServiceSchema{Version: "2010-08-01"})
							}
							client = cloudwatch.New(options)
							timestamps := alarmControlTimes{}
							histories := map[string][]any{}
							contributors := alarmContributorBindings{}
							drain := func() {
								t.Helper()
								result, err := cloud.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 1000)
								if err != nil || result.More {
									t.Fatalf("alarm jobs did not settle: %+v, %v", result, err)
								}
							}
							for _, step := range scenario.Steps {
								if !t.Run(step.Label, func(t *testing.T) {
									if err := source.Advance(time.Millisecond); err != nil {
										t.Fatal(err)
									}
									if step.At != "" {
										if err := source.Advance(nativeAlarmEvaluationTime(t, step.At).Sub(source.Now())); err != nil {
											t.Fatal(err)
										}
										drain()
									}
									for range step.AdvanceSeconds {
										if err := source.Advance(time.Second); err != nil {
											t.Fatal(err)
										}
										drain()
									}
									row := fixture.row(t, step.Label)
									resource := ""
									out := replayMetric(t, client, row, func(input any) {
										contributors.request(input)
										if query, ok := input.(*cloudwatch.DescribeAlarmContributorsInput); ok {
											resource = *query.AlarmName
										}
									})
									if step.Compare == "" {
										return
									}
									// Decode both sides through the SDK so optional fields and
									// list representations have the same public representation.
									native := reflect.New(reflect.TypeOf(out).Elem()).Interface()
									if err := awstest.DecodeSDK(row.Result.Output, native); err != nil {
										t.Fatal(err)
									}
									got, want := alarmControlObject(t, out), alarmControlObject(t, native)
									contributors.bind(t, got, want)
									if step.Compare == "history" || step.Compare == "contributor-history" {
										items, _ := got["AlarmHistoryItems"].([]any)
										if step.Retains != "" {
											previous, ok := histories[step.Retains]
											if !ok || len(items) < len(previous) || !reflect.DeepEqual(items[:len(previous)], previous) {
												t.Fatalf("previous history %q changed or disappeared: %v", step.Retains, items)
											}
										}
										histories[step.Label] = items
									}
									if step.Compare == "composite" {
										got = nativeAlarmCompositeProjection(t, got)
										want = nativeAlarmCompositeProjection(t, want)
									} else if step.Compare == "contributors" || step.Compare == "contributor-history" {
										got = alarmContributorProjection(t, got, step.Compare)
										want = alarmContributorProjection(t, want, step.Compare)
									} else {
										got = alarmControlProjection(t, got, step.Compare, 0)
										want = alarmControlProjection(t, want, step.Compare, step.HistorySince)
									}
									timestamps.compare(t, resource, got, want)
									if step.UpdatedAfterTransitionSeconds != 0 {
										for _, alarm := range out.(*cloudwatch.DescribeAlarmsOutput).CompositeAlarms {
											if alarm.StateUpdatedTimestamp == nil || alarm.StateTransitionedTimestamp == nil {
												t.Fatal("suppression expiration lacks state timestamps")
											}
											if delta := alarm.StateUpdatedTimestamp.Sub(*alarm.StateTransitionedTimestamp); delta != time.Duration(step.UpdatedAfterTransitionSeconds)*time.Second {
												t.Fatalf("suppression expiration updated-transitioned delta: got %s, native %ds", delta, step.UpdatedAfterTransitionSeconds)
											}
										}
									}
								}) {
									t.FailNow()
								}
							}
						})
					}
				}
			}
		})
	}
}

func alarmControlObject(t *testing.T, value any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func alarmControlFields(object map[string]any, fields string) map[string]any {
	result := map[string]any{}
	for _, field := range strings.Fields(fields) {
		result[field] = object[field]
	}
	return result
}

func alarmControlProjection(t *testing.T, object map[string]any, mode string, since int64) map[string]any {
	t.Helper()
	result := map[string]any{}
	switch mode {
	case "controls", "selection", "state", "contributor-parent":
		for _, kind := range []string{"MetricAlarms", "CompositeAlarms"} {
			alarms := []any{}
			items, _ := object[kind].([]any)
			for _, item := range items {
				alarm := item.(map[string]any)
				fields := "AlarmName AlarmArn"
				if mode == "controls" {
					fields += " AlarmDescription AlarmConfigurationUpdatedTimestamp ActionsEnabled OKActions AlarmActions InsufficientDataActions MetricName Namespace Statistic ExtendedStatistic Dimensions Period Unit EvaluationPeriods DatapointsToAlarm Threshold ComparisonOperator TreatMissingData EvaluateLowSampleCountPercentile Metrics ThresholdMetricId AlarmRule ActionsSuppressor ActionsSuppressorWaitPeriod ActionsSuppressorExtensionPeriod StateValue StateReason StateReasonData StateUpdatedTimestamp StateTransitionedTimestamp"
				}
				if mode == "state" || mode == "contributor-parent" {
					fields += " StateValue TreatMissingData"
				}
				if mode == "contributor-parent" {
					fields += " StateUpdatedTimestamp StateTransitionedTimestamp"
				}
				selected := alarmControlFields(alarm, fields)
				if mode == "state" {
					if reason, ok := alarm["StateReasonData"].(string); ok {
						var data map[string]any
						if err := json.Unmarshal([]byte(reason), &data); err != nil {
							t.Fatal(err)
						}
						// A held state must retain the caller's reason data. Native
						// evaluator timestamps are not inferred from local ticks.
						if _, evaluated := data["queryDate"]; !evaluated {
							selected["StateReasonData"] = data
						}
					}
				}
				// Creation/reset state matters; the service-generated initial prose
				// is not an oracle. All manually supplied reasons remain exact.
				if selected["StateValue"] == "INSUFFICIENT_DATA" && selected["StateReasonData"] == nil {
					delete(selected, "StateReason")
				}
				if dimensions, ok := selected["Dimensions"].([]any); ok {
					alarmControlSort(dimensions, "Name")
				}
				alarms = append(alarms, selected)
			}
			alarmControlSort(alarms, "AlarmName")
			result[kind] = alarms
		}
		result["NextToken"] = object["NextToken"]
	case "tags":
		tags, _ := object["Tags"].([]any)
		if tags == nil {
			tags = []any{}
		}
		alarmControlSort(tags, "Key")
		result["Tags"] = tags
	case "history":
		items := []any{}
		history, _ := object["AlarmHistoryItems"].([]any)
		for _, item := range history {
			record := item.(map[string]any)
			stamp, err := time.Parse(time.RFC3339Nano, record["Timestamp"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if since != 0 && stamp.UnixMilli() < since {
				continue
			}
			selected := alarmControlFields(record, "AlarmName AlarmType Timestamp HistoryItemType")
			var payload map[string]any
			if err := json.Unmarshal([]byte(record["HistoryData"].(string)), &payload); err != nil {
				t.Fatal(err)
			}
			if record["HistoryItemType"] == "StateUpdate" {
				for _, side := range []string{"oldState", "newState"} {
					state, ok := payload[side].(map[string]any)
					if !ok {
						t.Fatalf("history lacks %s: %v", side, payload)
					}
					if state["stateValue"] == "INSUFFICIENT_DATA" {
						delete(state, "stateReason")
					}
					selected[side] = state
				}
			} else {
				selected["type"] = payload["type"]
			}
			items = append(items, selected)
		}
		result["AlarmHistoryItems"] = items
		result["NextToken"] = object["NextToken"]
	default:
		t.Fatalf("unknown fixture comparison %q", mode)
	}
	return result
}

func alarmControlSort(items []any, key string) {
	sort.Slice(items, func(i, j int) bool {
		return items[i].(map[string]any)[key].(string) < items[j].(map[string]any)[key].(string)
	})
}

type alarmControlTimePair struct {
	native, local time.Time
}

type alarmControlTimes map[string][]alarmControlTimePair

// Bind opaque timestamps per resource and field. Repeated native values must
// stay equal locally; distinct earlier/later native values must preserve order.
// Unlike erasing timestamps, this detects same-state writes touching timestamps,
// failed writes committing, and recreation retaining the previous resource age.
func (times alarmControlTimes) compare(t *testing.T, path string, got, want any) {
	t.Helper()
	if expected, ok := want.([]any); ok && len(expected) == 0 && got == nil {
		return
	}
	if actual, ok := got.([]any); ok && len(actual) == 0 && want == nil {
		return
	}
	if expected, ok := want.(map[string]any); ok {
		actual, ok := got.(map[string]any)
		if !ok || len(actual) != len(expected) {
			t.Fatalf("%s fields: got %v, native %v", path, got, want)
		}
		if name, ok := expected["AlarmName"].(string); ok {
			path += "/" + name
		}
		for _, key := range []string{"ContributorId", "AlarmContributorId"} {
			if id, ok := expected[key].(string); ok {
				path += "/" + id
			}
		}
		for key, value := range expected {
			other, exists := actual[key]
			if !exists {
				t.Fatalf("%s missing field %s", path, key)
			}
			times.compare(t, path+"/"+key, other, value)
		}
		return
	}
	if expected, ok := want.([]any); ok {
		actual, ok := got.([]any)
		if !ok || len(actual) != len(expected) {
			t.Fatalf("%s collection: got %v, native %v", path, got, want)
		}
		for i := range expected {
			// A timestamp domain follows the resource, not a list position.
			times.compare(t, path, actual[i], expected[i])
		}
		return
	}
	if strings.HasSuffix(path, "Timestamp") && want != nil {
		native, err := time.Parse(time.RFC3339Nano, fmt.Sprint(want))
		if err != nil {
			t.Fatal(err)
		}
		local, err := time.Parse(time.RFC3339Nano, fmt.Sprint(got))
		if err != nil || local.IsZero() {
			t.Fatalf("%s invalid local timestamp %v", path, got)
		}
		for _, pair := range times[path] {
			if native.Compare(pair.native) != local.Compare(pair.local) {
				t.Fatalf("%s timestamp equality/order changed: native %v versus %v, local %v versus %v", path, native, pair.native, local, pair.local)
			}
			if native.Equal(pair.native) {
				return
			}
		}
		times[path] = append(times[path], alarmControlTimePair{native: native, local: local})
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: got %#v, native %#v", path, got, want)
	}
}
