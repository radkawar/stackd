package stackd_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"

	"stackd"
	"stackd/internal/awstest"
)

type nativeAlarmEvaluationState struct {
	Value      string          `json:"stateValue"`
	Reason     string          `json:"stateReason"`
	ReasonData json.RawMessage `json:"stateReasonData"`
}

type nativeAlarmEvaluationFixture struct {
	nativeMetricFixture
	Cases []struct {
		Name           string
		Creation       string
		Publications   []string
		EvaluationTime string                     `json:"evaluation_time"`
		CadenceSeconds int64                      `json:"cadence_seconds"`
		PriorState     nativeAlarmEvaluationState `json:"prior_state"`
		Expected       nativeAlarmEvaluationState
		Evidence       struct {
			Limitation string
		}
	}
}

// These are independent native evaluations, not a replay of AWS processing
// latency. In particular, a later Describe request is never the clock oracle.
// The fixture retains unreplayable early snapshots and explains their limits.
func TestCloudWatchNativeAlarmEvaluation(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/cloudwatch/alarm_evaluation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture nativeAlarmEvaluationFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, test := range fixture.Cases {
			t.Run(backend+"/"+test.Name, func(t *testing.T) {
				if test.Evidence.Limitation != "" {
					t.Log(test.Evidence.Limitation)
				}
				queryDate := nativeAlarmEvaluationTime(t, test.EvaluationTime)
				created := queryDate.Add(-time.Duration(test.CadenceSeconds) * time.Second)
				rows := fixture.nativeMetricFixture
				rows.Scope.Anchor = created.Unix()
				cloud, source := metricFixtureCloud(t, backend, rows)
				if err := source.Advance(created.Sub(source.Now())); err != nil {
					t.Fatal(err)
				}
				client := metricsClient(cloud, "test")
				creation := rows.row(t, test.Creation)
				replayMetric(t, client, creation)
				var alarm struct{ AlarmName string }
				if err := json.Unmarshal(creation.Input, &alarm); err != nil {
					t.Fatal(err)
				}
				for _, publication := range test.Publications {
					// Keep original sample timestamps, even for older publications
					// that may have expired. Never synthesize missing datapoints.
					replayMetric(t, client, rows.row(t, publication))
				}
				call := func(operation string, input any) any {
					t.Helper()
					encoded, err := json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					out, err := awstest.CallSDK(t.Context(), client, operation, encoded)
					if err != nil {
						t.Fatalf("%s: %v", operation, err)
					}
					return out
				}
				// Noninitial prior states come from native HistoryData.oldState,
				// not from guessing what an earlier local evaluation would do.
				if test.PriorState.Value != "INSUFFICIENT_DATA" || len(test.PriorState.ReasonData) != 0 {
					input := map[string]any{
						"AlarmName":   alarm.AlarmName,
						"StateValue":  test.PriorState.Value,
						"StateReason": test.PriorState.Reason,
					}
					if len(test.PriorState.ReasonData) != 0 {
						input["StateReasonData"] = string(test.PriorState.ReasonData)
					}
					call("SetAlarmState", input)
				}
				if err := source.Advance(queryDate.Sub(source.Now())); err != nil {
					t.Fatal(err)
				}
				drain, err := cloud.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 100)
				if err != nil || drain.More {
					t.Fatalf("evaluation did not drain: %+v, %v", drain, err)
				}
				out := call("DescribeAlarms", map[string]any{"AlarmNames": []string{alarm.AlarmName}}).(*cloudwatch.DescribeAlarmsOutput)
				if len(out.MetricAlarms) != 1 {
					t.Fatalf("expected one alarm, got %d", len(out.MetricAlarms))
				}
				got := out.MetricAlarms[0]
				if string(got.StateValue) != test.Expected.Value {
					t.Fatalf("state at native queryDate %s: got %s, want %s; reason data %s", test.EvaluationTime, got.StateValue, test.Expected.Value, aws.ToString(got.StateReasonData))
				}
				var actual json.RawMessage
				if got.StateReasonData != nil {
					actual = json.RawMessage(*got.StateReasonData)
				}
				wantReason := nativeAlarmEvaluationReason(t, test.Expected.ReasonData)
				gotReason := nativeAlarmEvaluationReason(t, actual)
				if !reflect.DeepEqual(gotReason, wantReason) {
					t.Fatalf("reason data at native queryDate %s:\n got %s\nwant %s", test.EvaluationTime, actual, test.Expected.ReasonData)
				}
			})
		}
	}
}

func nativeAlarmEvaluationTime(t *testing.T, value string) time.Time {
	t.Helper()
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	t.Fatalf("invalid native evaluation timestamp %q", value)
	return time.Time{}
}

func nativeAlarmEvaluationReason(t *testing.T, data json.RawMessage) map[string]any {
	t.Helper()
	if len(data) == 0 {
		return nil
	}
	var reason map[string]any
	if err := json.Unmarshal(data, &reason); err != nil {
		t.Fatal(err)
	}
	// Compare the structured consumer evidence, not its schema-version default,
	// timestamp spelling, or human-readable prose. Null gaps and absent scalar
	// sampleCount/statistic/unit fields in expression results remain significant.
	delete(reason, "version")
	for _, field := range []string{"queryDate", "startDate"} {
		if value, ok := reason[field].(string); ok {
			reason[field] = nativeAlarmEvaluationTime(t, value)
		}
	}
	if points, ok := reason["evaluatedDatapoints"].([]any); ok {
		for _, item := range points {
			point, ok := item.(map[string]any)
			if !ok {
				t.Fatalf("invalid evaluated datapoint: %v", item)
			}
			if value, ok := point["timestamp"].(string); ok {
				point["timestamp"] = nativeAlarmEvaluationTime(t, value)
			}
		}
	}
	return reason
}
