package stackd_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/internal/awstest"
)

type contributorDeliveryFixture struct {
	Account      string `json:"caller_account"`
	Region       string
	Observations []awsNativeObservation
	Phases       []struct {
		Label        string
		Values       map[string]float64
		ConvergedAt  *string        `json:"converged_at"`
		Parent       map[string]any `json:"last_observed_parent"`
		Contributors map[string]any `json:"last_observed_contributors"`
	}
	Deliveries []struct {
		Phase     string `json:"observed_phase"`
		Transport string
		Envelope  map[string]any
		Payload   map[string]any
	}
}

// Replay the four converged native phases, not their polling latency or the
// interrupted pre-resume snapshot. Both consumers are real services: non-raw
// SNS -> SQS and unchanged EventBridge -> SQS, sharing the captured queue policy.
func TestCloudWatchNativeContributorDelivery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var fixture contributorDeliveryFixture
			awsReadFixture(t, "cloudwatch/metric_insights_contributor_delivery.json", &fixture)
			cloud, clients, source := admissionFixtureCloud(t, backend, snsAdmissionFixture{
				Account: fixture.Account, Region: fixture.Region, Observations: fixture.Observations,
			})
			alarmOptions := metricsClient(clients, fixture.Account).Options()
			alarmOptions.Region = fixture.Region
			alarms := cloudwatch.New(alarmOptions)
			queueOptions := clients.sqs(fixture.Account, "test", "").Options()
			queueOptions.Region = fixture.Region
			queues := sqs.New(queueOptions)
			eventOptions := eventDeliveryClient(clients, fixture.Account).Options()
			eventOptions.Region = fixture.Region
			events := eventbridge.New(eventOptions)
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			rows := make(map[string]awsNativeObservation, len(fixture.Observations))
			for _, row := range fixture.Observations {
				rows[row.Label] = row
			}
			row := func(label string) awsNativeObservation {
				t.Helper()
				observation, ok := rows[label]
				if !ok {
					t.Fatalf("missing native observation %s", label)
				}
				return observation
			}
			var queueURL *string
			advanceClock(t, source, source.Now().Truncate(time.Minute).Add(time.Minute+time.Second).Sub(source.Now()))
			for _, label := range []string{"create-queue", "create-topic", "create-rule", "topic-policy", "queue-policy", "subscribe", "event-target", "create-alarm"} {
				call := row(label)
				client := map[string]any{"sqs": queues, "sns": topics, "events": events, "cloudwatch": alarms}[call.Service]
				out, err := awstest.CallSDK(t.Context(), client, call.Operation, call.Input, func(input any) {
					if input, ok := input.(*sqs.SetQueueAttributesInput); ok {
						input.QueueUrl = queueURL
					}
				})
				awsNativeResult(t, call, err)
				switch out := out.(type) {
				case *sqs.CreateQueueOutput:
					queueURL = out.QueueUrl
				case *eventbridge.PutTargetsOutput:
					if out.FailedEntryCount != 0 {
						t.Fatalf("native target admission failed: %+v", out)
					}
				}
			}
			comparison := contributorDeliveryComparison{ids: alarmContributorBindings{}, times: alarmControlTimes{}}
			for _, phase := range fixture.Phases {
				if phase.ConvergedAt == nil {
					continue
				}
				t.Logf("native phase: %s", phase.Label)
				call := row("initial-publish")
				_, err := awstest.CallSDK(t.Context(), alarms, call.Operation, call.Input, func(input any) {
					publication := input.(*cloudwatch.PutMetricDataInput)
					for i := range publication.MetricData {
						metric := &publication.MetricData[i]
						identity := aws.ToString(metric.Dimensions[0].Value)
						value, exists := phase.Values[identity]
						if !exists {
							t.Fatalf("phase %s lacks captured metric identity %s", phase.Label, identity)
						}
						metric.Value, metric.Timestamp = aws.Float64(value), aws.Time(source.Now())
					}
				})
				awsNativeResult(t, call, err)
				advanceClock(t, source, time.Minute)
				messages := snsAdmissionReceive(t, cloud, queues, queueURL)
				name := phase.Parent["AlarmName"].(string)
				parent, err := alarms.DescribeAlarms(t.Context(), &cloudwatch.DescribeAlarmsInput{AlarmNames: []string{name}})
				if err != nil || len(parent.MetricAlarms) != 1 {
					t.Fatalf("parent discovery: %+v, %v", parent, err)
				}
				fields := "StateValue StateUpdatedTimestamp StateTransitionedTimestamp"
				comparison.compare(t, "parent", alarmControlFields(alarmControlObject(t, parent.MetricAlarms[0]), fields), alarmControlFields(phase.Parent, fields))
				contributors, err := alarms.DescribeAlarmContributors(t.Context(), &cloudwatch.DescribeAlarmContributorsInput{AlarmName: &name})
				if err != nil {
					t.Fatal(err)
				}
				actual := alarmControlObject(t, contributors)
				comparison.ids.bind(t, actual, phase.Contributors)
				comparison.compare(t, "active", alarmContributorProjection(t, actual, "contributors"), alarmContributorProjection(t, phase.Contributors, "contributors"))

				expected := map[string]map[string]any{}
				for _, delivery := range fixture.Deliveries {
					if delivery.Phase != phase.Label {
						continue
					}
					document := delivery.Payload
					if delivery.Transport == "SNS" {
						document = delivery.Envelope
					}
					key := contributorDeliveryKey(t, document)
					if _, exists := expected[key]; exists {
						t.Fatalf("ambiguous native delivery %s", key)
					}
					expected[key] = document
				}
				for _, message := range messages {
					var document map[string]any
					awsDecodeJSON(t, json.RawMessage(aws.ToString(message.Body)), &document)
					key := contributorDeliveryKey(t, document)
					want, exists := expected[key]
					if !exists {
						t.Fatalf("%s: unexpected consumer delivery %s: %v", phase.Label, key, document)
					}
					comparison.compare(t, key, document, want)
					delete(expected, key)
				}
				if len(expected) != 0 {
					t.Fatalf("%s: missing native consumer deliveries %v", phase.Label, expected)
				}
				// These cumulative public histories detect reason-only parent
				// updates, while the drained queue detects spurious parent events
				// or actions during unchanged ALARM phases.
				for _, kind := range []string{"StateUpdate", "Action", "AlarmContributorStateUpdate", "AlarmContributorAction"} {
					call := row(phase.Label + "-end-history-" + kind)
					out, err := awstest.CallSDK(t.Context(), alarms, call.Operation, call.Input)
					awsNativeResult(t, call, err)
					actual := alarmControlObject(t, out)
					var expected map[string]any
					awsDecodeJSON(t, call.Result.Output, &expected)
					comparison.ids.bind(t, actual, expected)
					comparison.compare(t, "history/"+kind, contributorDeliveryHistory(t, actual), contributorDeliveryHistory(t, expected))
				}
			}
		})
	}
}

func contributorDeliveryKey(t *testing.T, document map[string]any) string {
	t.Helper()
	if document["Type"] == "Notification" {
		var payload map[string]any
		awsDecodeJSON(t, json.RawMessage(fmt.Sprint(document["Message"])), &payload)
		return fmt.Sprint("SNS/", payload["AlarmContributorAttributes"], "/", payload["NewStateValue"])
	}
	return fmt.Sprint(document["detail-type"], "/", awsFixtureField(document, "detail.alarmContributor.attributes"), "/", awsFixtureField(document, "detail.state.value"))
}

func contributorDeliveryHistory(t *testing.T, object map[string]any) map[string]any {
	t.Helper()
	projected := alarmContributorProjection(t, object, "contributor-history")
	for i, raw := range projected["AlarmHistoryItems"].([]any) {
		item := raw.(map[string]any)
		if item["HistoryItemType"] == "StateUpdate" {
			original := object["AlarmHistoryItems"].([]any)[i].(map[string]any)
			var data map[string]any
			awsDecodeJSON(t, json.RawMessage(original["HistoryData"].(string)), &data)
			item["data"].(map[string]any)["reasonChanged"] = awsFixtureField(data, "oldState.stateReason") != awsFixtureField(data, "newState.stateReason")
		}
		if item["HistoryItemType"] == "AlarmContributorAction" {
			// Generated email/SMS prose is not the SQS consumer contract. The
			// actual notification document is compared in full above.
			item["data"] = alarmControlFields(item["data"].(map[string]any), "actionState stateUpdateTimestamp notificationResource error muteWindowEndTimestamp")
		}
	}
	return projected
}

type contributorDeliveryComparison struct {
	ids   alarmContributorBindings
	times alarmControlTimes
}

func (c *contributorDeliveryComparison) compare(t *testing.T, path string, got, want any) {
	t.Helper()
	if expected, ok := want.(map[string]any); ok {
		actual, ok := got.(map[string]any)
		if !ok || len(actual) != len(expected) {
			t.Fatalf("%s fields: local %v; native %v", path, got, want)
		}
		for key, value := range expected {
			other, exists := actual[key]
			if !exists {
				t.Fatalf("%s missing native field %s", path, key)
			}
			child := path + "/" + key
			switch key {
			case "Message", "reasonData":
				var local, native map[string]any
				awsDecodeJSON(t, json.RawMessage(fmt.Sprint(other)), &local)
				awsDecodeJSON(t, json.RawMessage(fmt.Sprint(value)), &native)
				c.compare(t, child, local, native)
				continue
			case "ContributorId", "AlarmContributorId":
				if value != nil {
					contributorDeliveryOpaque(t, child, other)
				}
				if bound, exists := c.ids[fmt.Sprint(value)]; exists {
					value = bound
				}
			case "id":
				if strings.HasSuffix(path, "/alarmContributor") {
					contributorDeliveryOpaque(t, child, other)
					value = c.ids[fmt.Sprint(value)]
				} else if _, event := expected["detail-type"]; event {
					c.bindOpaque(t, child, other, value)
					continue
				}
			case "MessageId":
				c.bindOpaque(t, child, other, value)
				continue
			case "reason", "stateReason", "NewStateReason", "Signature", "SigningCertURL", "UnsubscribeURL":
				contributorDeliveryOpaque(t, child, other)
				continue
			case "time":
				nativeAlarmEvaluationTime(t, fmt.Sprint(other))
				continue
			case "timestamp", "Timestamp", "StateChangeTime", "StateUpdatedTimestamp", "StateTransitionedTimestamp", "AlarmConfigurationUpdatedTimestamp", "stateUpdateTimestamp", "queryDate":
				if value == nil {
					break
				}
				local, native := fmt.Sprint(other), fmt.Sprint(value)
				if key == "stateUpdateTimestamp" {
					localMS, localOK := other.(float64)
					nativeMS, nativeOK := value.(float64)
					if !localOK || !nativeOK {
						t.Fatalf("%s must remain epoch milliseconds: %v", child, other)
					}
					local = time.UnixMilli(int64(localMS)).UTC().Format(time.RFC3339Nano)
					native = time.UnixMilli(int64(nativeMS)).UTC().Format(time.RFC3339Nano)
				}
				local = nativeAlarmEvaluationTime(t, local).Format(time.RFC3339Nano)
				native = nativeAlarmEvaluationTime(t, native).Format(time.RFC3339Nano)
				if key == "Timestamp" && expected["Type"] == "Notification" {
					continue // SNS send time is not the alarm's transition time.
				}
				domain := "stateTimestamp"
				if key == "queryDate" {
					domain = "queryTimestamp"
				} else if key == "Timestamp" && expected["HistoryItemType"] == "AlarmContributorAction" {
					domain = "actionTimestamp"
				}
				c.times.compare(t, domain, local, native)
				continue
			}
			c.compare(t, child, other, value)
		}
		return
	}
	if expected, ok := want.([]any); ok {
		actual, ok := got.([]any)
		if len(expected) == 0 && got == nil && strings.HasPrefix(path, "history/") {
			return // SDK slices do not retain wire absent versus empty.
		}
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

func (c *contributorDeliveryComparison) bindOpaque(t *testing.T, path string, got, want any) {
	t.Helper()
	contributorDeliveryOpaque(t, path, got)
	local, native := got.(string), want.(string)
	if previous, exists := c.ids[native]; exists && previous != local {
		t.Fatalf("%s opaque ID equality changed: %s became %s", path, previous, local)
	}
	for other, bound := range c.ids {
		if other != native && bound == local {
			t.Fatalf("%s distinct native IDs %s and %s collapsed into %s", path, other, native, local)
		}
	}
	c.ids[native] = local
}

func contributorDeliveryOpaque(t *testing.T, path string, value any) {
	t.Helper()
	if text, ok := value.(string); !ok || text == "" {
		t.Fatalf("%s must remain a nonempty string: %v", path, value)
	}
}
