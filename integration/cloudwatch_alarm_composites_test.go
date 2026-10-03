package stackd_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"stackd"
)

type nativeAlarmCompositeFixture struct {
	nativeMetricFixture
	DerivedRules struct {
		Evidence  string
		Setup     []string
		AlarmName string `json:"alarm_name"`
		Cases     []struct {
			Name, Rule    string
			ExpectedState string `json:"expected_state"`
		}
	} `json:"derived_rules"`
}

func TestCloudWatchNativeAlarmComposites(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/cloudwatch/alarm_composites.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture nativeAlarmCompositeFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend+"/derived-boolean-contract", func(t *testing.T) {
			t.Log(fixture.DerivedRules.Evidence)
			cloud, source := metricFixtureCloud(t, backend, fixture.nativeMetricFixture)
			client := metricsClient(cloud, "test")
			for _, label := range fixture.DerivedRules.Setup {
				replayMetric(t, client, fixture.row(t, label))
			}
			for _, test := range fixture.DerivedRules.Cases {
				if !t.Run(test.Name, func(t *testing.T) {
					_, err := client.PutCompositeAlarm(t.Context(), &cloudwatch.PutCompositeAlarmInput{
						AlarmName:      aws.String(fixture.DerivedRules.AlarmName),
						AlarmRule:      aws.String(test.Rule),
						ActionsEnabled: aws.Bool(false),
					})
					if err != nil {
						t.Fatal(err)
					}
					if err := source.Advance(time.Second); err != nil {
						t.Fatal(err)
					}
					result, err := cloud.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 1000)
					if err != nil || result.More {
						t.Fatalf("rule evaluation did not settle: %+v, %v", result, err)
					}
					out, err := client.DescribeAlarms(t.Context(), &cloudwatch.DescribeAlarmsInput{
						AlarmNames: []string{fixture.DerivedRules.AlarmName},
						AlarmTypes: []types.AlarmType{types.AlarmTypeCompositeAlarm},
					})
					if err != nil {
						t.Fatal(err)
					}
					if len(out.CompositeAlarms) != 1 || string(out.CompositeAlarms[0].StateValue) != test.ExpectedState {
						t.Fatalf("rule %q: got %+v, want state %s", test.Rule, out.CompositeAlarms, test.ExpectedState)
					}
				}) {
					t.FailNow()
				}
			}
		})
	}
}

func nativeAlarmCompositeProjection(t *testing.T, object map[string]any) map[string]any {
	t.Helper()
	projected := alarmControlProjection(t, object, "controls", 0)
	for _, kind := range []string{"MetricAlarms", "CompositeAlarms"} {
		original := map[string]map[string]any{}
		items, _ := object[kind].([]any)
		for _, item := range items {
			alarm := item.(map[string]any)
			original[alarm["AlarmName"].(string)] = alarm
		}
		for _, item := range projected[kind].([]any) {
			alarm := item.(map[string]any)
			raw := original[alarm["AlarmName"].(string)]
			// Preserve absence versus presence, without pinning computed prose.
			alarm["StateReasonPresent"] = raw["StateReason"] != nil
			delete(alarm, "StateReason")
			if kind == "CompositeAlarms" {
				alarm["ActionsSuppressedBy"] = raw["ActionsSuppressedBy"]
				alarm["ActionsSuppressedReasonPresent"] = raw["ActionsSuppressedReason"] != nil
			}
			if reason, ok := raw["StateReasonData"].(string); ok {
				alarm["StateReasonData"] = nativeAlarmCompositeReason(t, reason)
			}
		}
	}
	return projected
}

func nativeAlarmCompositeReason(t *testing.T, reason string) map[string]any {
	t.Helper()
	var data map[string]any
	if err := json.Unmarshal([]byte(reason), &data); err != nil {
		t.Fatal(err)
	}
	if witnesses, ok := data["triggeringAlarms"].([]any); ok {
		for _, item := range witnesses {
			witness := item.(map[string]any)
			// The shared relation helper keys opaque times by AlarmName. Use
			// the captured witness ARN as that identity, without erasing any
			// structured evidence or comparing service timestamp spelling.
			witness["AlarmName"] = witness["arn"]
			state, ok := witness["state"].(map[string]any)
			if !ok {
				t.Fatalf("triggering alarm lacks structured state: %v", witness)
			}
			if stamp, ok := state["timestamp"].(string); ok {
				state["Timestamp"] = nativeAlarmEvaluationTime(t, stamp).Format(time.RFC3339Nano)
				delete(state, "timestamp")
			}
		}
		alarmControlSort(witnesses, "AlarmName")
	}
	return data
}
