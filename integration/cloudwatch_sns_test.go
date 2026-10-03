package stackd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
)

type cloudWatchSNSFixture struct {
	snsAdmissionFixture
	Deliveries []struct {
		SourceLabel string `json:"source_label"`
		Case        string
		Envelope    snsAdmissionNotification
	}
}

func cloudWatchSNSCapture(t *testing.T) cloudWatchSNSFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/cloudwatch/sns_publications.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture cloudWatchSNSFixture
	awsDecodeJSON(t, data, &fixture)
	return fixture
}

func TestCloudWatchNativeSNSPublications(t *testing.T) {
	fixture := cloudWatchSNSCapture(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, limitation := range fixture.Limitations {
				t.Log(limitation)
			}
			cloud, clients, source := admissionFixtureCloud(t, backend, fixture.snsAdmissionFixture)
			cloudWatchSNSReplay(t, fixture, cloud, clients, source, nil)
		})
	}
}

func TestCloudWatchSNSPublicationSurvivesSQLiteRestart(t *testing.T) {
	fixture := cloudWatchSNSCapture(t)
	path := filepath.Join(t.TempDir(), "cloudwatch-sns.sqlite")
	backends, closeDatabase := openSQLiteBackends(t, path)
	source := clock.NewManual(time.UnixMilli(fixture.Observations[0].Started).UTC())
	cloud, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
	cloudWatchSNSReplay(t, fixture, cloud, clients, source, func() (*stackd.Stack, cloudClients) {
		closeCloud()
		closeDatabase()
		backends, _ = openSQLiteBackends(t, path)
		reopened, connected, _ := startEventDeliveryCloud(t, backends, source)
		return reopened, connected
	})
}

// All admission and consumption uses actual SDK HTTP calls. Evaluation stops at
// the observed composite state before action dispatch; deleting/mutating sources
// before delivery distinguishes retained documents from current configuration.
func cloudWatchSNSReplay(t *testing.T, fixture cloudWatchSNSFixture, cloud *stackd.Stack, clients cloudClients, source *clock.Manual, reopen func() (*stackd.Stack, cloudClients)) {
	t.Helper()
	topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
	queues := clients.sqs(fixture.Account, "test", "")
	alarms := metricsClient(clients, fixture.Account)
	var queueURL *string
	var queueName string
	var mutations []cloudwatch.PutMetricAlarmInput
	var names []string
	var parent string
	observations := make(map[string]awsNativeObservation, len(fixture.Observations))
	for _, row := range fixture.Observations {
		observations[row.Label] = row
	}
	// Evaluate the child-driven case first so single-job stepping can stop at
	// ALARM without dispatching unrelated actions. Native wall-time latency is
	// intentionally not replayed; state/configuration times are rebound below.
	for _, label := range []string{
		"create-owned-topic", "create-owned-queue", "grant-exact-owned-topic", "subscribe-signed-envelope",
		"put-child", "initialize-child-ok", "put-composite", "trigger-child-actual-alarm-transition",
		"put-long-ascii", "trigger-long-ascii", "put-long-unicode", "trigger-long-unicode", "put-metric-query", "trigger-metric-query",
	} {
		row, exists := observations[label]
		if !exists {
			t.Fatalf("missing native request %s", label)
		}
		var err error
		switch row.Operation {
		case "create-topic":
			var in sns.CreateTopicInput
			awsDecodeJSON(t, row.Input, &in)
			_, err = topics.CreateTopic(t.Context(), &in)
		case "create-queue":
			var in sqs.CreateQueueInput
			awsDecodeJSON(t, row.Input, &in)
			var out *sqs.CreateQueueOutput
			out, err = queues.CreateQueue(t.Context(), &in)
			if err == nil {
				queueURL, queueName = out.QueueUrl, aws.ToString(in.QueueName)
			}
		case "set-queue-attributes":
			var in sqs.SetQueueAttributesInput
			awsDecodeJSON(t, row.Input, &in)
			in.QueueUrl = queueURL
			_, err = queues.SetQueueAttributes(t.Context(), &in)
		case "subscribe":
			var in sns.SubscribeInput
			awsDecodeJSON(t, row.Input, &in)
			_, err = topics.Subscribe(t.Context(), &in)
		case "put-metric-alarm":
			if err := source.Advance(time.Millisecond); err != nil {
				t.Fatal(err)
			}
			var in cloudwatch.PutMetricAlarmInput
			awsDecodeJSON(t, row.Input, &in)
			_, err = alarms.PutMetricAlarm(t.Context(), &in)
			mutations = append(mutations, in)
			names = append(names, aws.ToString(in.AlarmName))
		case "put-composite-alarm":
			if err := source.Advance(time.Millisecond); err != nil {
				t.Fatal(err)
			}
			var in cloudwatch.PutCompositeAlarmInput
			awsDecodeJSON(t, row.Input, &in)
			_, err = alarms.PutCompositeAlarm(t.Context(), &in)
			parent = aws.ToString(in.AlarmName)
		case "set-alarm-state":
			if err := source.Advance(time.Millisecond); err != nil {
				t.Fatal(err)
			}
			var in cloudwatch.SetAlarmStateInput
			awsDecodeJSON(t, row.Input, &in)
			_, err = alarms.SetAlarmState(t.Context(), &in)
		default:
			continue // Native read results below are comparison evidence, not commands.
		}
		awsNativeResult(t, row, err)
		if label == "put-composite" || label == "trigger-child-actual-alarm-transition" {
			expectedState := cwtypes.StateValueOk
			if label == "trigger-child-actual-alarm-transition" {
				expectedState = cwtypes.StateValueAlarm
				if err := source.Advance(time.Second); err != nil {
					t.Fatal(err)
				}
			}
			for step := 0; ; step++ {
				state, err := alarms.DescribeAlarms(t.Context(), &cloudwatch.DescribeAlarmsInput{AlarmNames: []string{parent}, AlarmTypes: []cwtypes.AlarmType{cwtypes.AlarmTypeCompositeAlarm}})
				if err != nil {
					t.Fatal(err)
				}
				if len(state.CompositeAlarms) == 1 && state.CompositeAlarms[0].StateValue == expectedState {
					break
				}
				if step == 1000 {
					t.Fatalf("child-driven composite did not reach %s", expectedState)
				}
				if _, err := cloud.RunDueJobs(t.Context(), 1); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	retained, err := alarms.DescribeAlarms(t.Context(), &cloudwatch.DescribeAlarmsInput{AlarmNames: append(append([]string{}, names...), parent), AlarmTypes: []cwtypes.AlarmType{cwtypes.AlarmTypeMetricAlarm, cwtypes.AlarmTypeCompositeAlarm}})
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]time.Time{}
	configured := map[string]time.Time{}
	reasons := map[string]string{}
	for _, alarm := range retained.MetricAlarms {
		name := aws.ToString(alarm.AlarmName)
		states[name], configured[name], reasons[name] = *alarm.StateUpdatedTimestamp, *alarm.AlarmConfigurationUpdatedTimestamp, aws.ToString(alarm.StateReason)
	}
	for _, alarm := range retained.CompositeAlarms {
		states[aws.ToString(alarm.AlarmName)], reasons[aws.ToString(alarm.AlarmName)] = *alarm.StateUpdatedTimestamp, aws.ToString(alarm.StateReason)
	}
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	for _, in := range mutations {
		in.AlarmDescription, in.AlarmActions, in.Threshold = aws.String("mutated after acceptance"), nil, aws.Float64(999)
		if _, err := alarms.PutMetricAlarm(t.Context(), &in); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := alarms.DeleteAlarms(t.Context(), &cloudwatch.DeleteAlarmsInput{AlarmNames: []string{parent}}); err != nil {
		t.Fatal(err)
	}
	if _, err := alarms.DeleteAlarms(t.Context(), &cloudwatch.DeleteAlarmsInput{AlarmNames: names}); err != nil {
		t.Fatal(err)
	}
	if reopen != nil {
		cloud, clients = reopen()
		queues, alarms = clients.sqs(fixture.Account, "test", ""), metricsClient(clients, fixture.Account)
		queue, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: &queueName})
		if err != nil {
			t.Fatal(err)
		}
		queueURL = queue.QueueUrl
	}
	received := map[string]snsAdmissionNotification{}
	for _, message := range snsAdmissionReceive(t, cloud, queues, queueURL) {
		var envelope snsAdmissionNotification
		awsDecodeJSON(t, json.RawMessage(aws.ToString(message.Body)), &envelope)
		var document struct{ AlarmName string }
		awsDecodeJSON(t, json.RawMessage(envelope.Message), &document)
		if previous, duplicate := received[document.AlarmName]; duplicate {
			// Standard SNS/SQS delivery is at least once, including recovery
			// after publication commits but before its acknowledgement.
			if previous.Type != envelope.Type || previous.Message != envelope.Message || aws.ToString(previous.Subject) != aws.ToString(envelope.Subject) {
				t.Fatalf("alarm redelivery changed retained content: before=%+v after=%+v", previous, envelope)
			}
		}
		received[document.AlarmName] = envelope
	}
	for _, native := range fixture.Deliveries {
		var want map[string]any
		awsDecodeJSON(t, json.RawMessage(native.Envelope.Message), &want)
		name := want["AlarmName"].(string)
		got, ok := received[name]
		if !ok {
			t.Fatalf("%s/%s: retained publication not delivered", native.SourceLabel, native.Case)
		}
		delete(received, name)
		if got.Type != "Notification" || aws.ToString(got.Subject) != aws.ToString(native.Envelope.Subject) {
			t.Fatalf("%s: native subject transformation lost: %+v", native.Case, got)
		}
		var document map[string]any
		awsDecodeJSON(t, json.RawMessage(got.Message), &document)
		want["StateChangeTime"] = states[name].UTC().Format("2006-01-02T15:04:05.000-0700")
		if at, scalar := configured[name]; scalar {
			want["AlarmConfigurationUpdatedTimestamp"] = at.UTC().Format("2006-01-02T15:04:05.000-0700")
		}
		// Composite evaluator prose is not the SNS contract. Its actual retained
		// child state/time is: never substitute publication/delivery/current time.
		want["NewStateReason"] = reasons[name]
		if children, composite := want["TriggeringChildren"].([]any); composite {
			for _, value := range children {
				child := value.(map[string]any)
				childName := strings.SplitN(child["Arn"].(string), ":alarm:", 2)[1]
				child["State"].(map[string]any)["Timestamp"] = states[childName].UTC().Format("2006-01-02T15:04:05.000-0700")
			}
		}
		if !reflect.DeepEqual(document, want) {
			t.Fatalf("%s: native alarm body fields differ\ngot: %#v\nwant: %#v", native.Case, document, want)
		}
		alarmType := cwtypes.AlarmTypeMetricAlarm
		if native.Case == "composite" {
			alarmType = cwtypes.AlarmTypeCompositeAlarm
		}
		history, err := alarms.DescribeAlarmHistory(t.Context(), &cloudwatch.DescribeAlarmHistoryInput{AlarmName: &name, AlarmTypes: []cwtypes.AlarmType{alarmType}, HistoryItemType: cwtypes.HistoryItemTypeAction})
		if err != nil {
			t.Fatal(err)
		}
		var nativeHistory map[string]any
		for _, row := range fixture.Observations {
			if row.Operation != "describe-alarm-history" {
				continue
			}
			var out cloudwatch.DescribeAlarmHistoryOutput
			awsDecodeJSON(t, row.Result.Output, &out)
			for _, item := range out.AlarmHistoryItems {
				if aws.ToString(item.AlarmName) == name && item.HistoryItemType == cwtypes.HistoryItemTypeAction {
					awsDecodeJSON(t, json.RawMessage(aws.ToString(item.HistoryData)), &nativeHistory)
				}
			}
		}
		if nativeHistory == nil {
			t.Fatalf("missing native history evidence for %s", name)
		}
		var nativePublication map[string]string
		awsDecodeJSON(t, json.RawMessage(nativeHistory["publishedMessage"].(string)), &nativePublication)
		if nativePublication["default"] != native.Envelope.Message {
			t.Fatalf("capture history/default differs from actual SQS message for %s", name)
		}
		matched := false
		for _, item := range history.AlarmHistoryItems {
			var data map[string]any
			awsDecodeJSON(t, json.RawMessage(aws.ToString(item.HistoryData)), &data)
			if data["actionState"] != "Succeeded" {
				t.Fatalf("retained SNS action failed: %s", aws.ToString(item.HistoryData))
			}
			var publication map[string]string
			published, ok := data["publishedMessage"].(string)
			if !ok {
				t.Fatalf("successful SNS history lacks structured publication string: %#v", data)
			}
			awsDecodeJSON(t, json.RawMessage(published), &publication)
			if publication["default"] != got.Message || publication["sms"] != nativePublication["sms"] {
				t.Fatalf("%s: published default/SMS is not authoritative", native.Case)
			}
			cloudWatchSNSEmailDetails(t, publication["email"], nativePublication["email"], name, states[name], reasons[name])
			if children, composite := want["TriggeringChildren"].([]any); composite {
				for _, value := range children {
					child := value.(map[string]any)
					childState := child["State"].(map[string]any)
					childAt, err := time.Parse("2006-01-02T15:04:05.000-0700", childState["Timestamp"].(string))
					if err != nil {
						t.Fatal(err)
					}
					expected := strings.Join([]string{"-", child["Arn"].(string), childState["Value"].(string), childAt.UTC().Format("Monday 2 January, 2006 15:04:05 MST")}, " ")
					found := false
					for _, line := range strings.Split(publication["email"], "\n") {
						if strings.Join(strings.Fields(line), " ") == expected {
							found = true
						}
					}
					if !found {
						t.Fatalf("native composite email lost retained child transition: %s", expected)
					}
				}
			}
			nativeHistory["publishedMessage"], nativeHistory["stateUpdateTimestamp"] = published, float64(states[name].UnixMilli())
			if !reflect.DeepEqual(data, nativeHistory) {
				t.Fatalf("%s: native SNS history fields differ\ngot: %#v\nwant: %#v", native.Case, data, nativeHistory)
			}
			matched = true
		}
		if !matched {
			t.Fatalf("%s: successful SNS history missing after source deletion", native.Case)
		}
	}
	if len(received) != 0 {
		t.Fatalf("unexpected alarm publications after source mutation: %#v", received)
	}
}

// Compare email's observable data projection, not a golden copy of generic prose
// or alignment whitespace. Subject/SMS sanitize the name; email retains Unicode,
// escapes the console URL, and has distinct scalar/query/composite detail fields.
func cloudWatchSNSEmailDetails(t *testing.T, got, native, name string, at time.Time, reason string) {
	t.Helper()
	project := func(body string) map[string]string {
		fields := map[string]string{}
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, "https://") {
				fields["ConsoleURL"] = line
				continue
			}
			if !strings.HasPrefix(line, "- ") {
				continue
			}
			key, value, ok := strings.Cut(strings.TrimPrefix(line, "- "), ":")
			if !ok || key == "arn" {
				continue
			}
			fields[key] = strings.TrimSpace(value)
		}
		return fields
	}
	want, actual := project(native), project(got)
	want["Timestamp"], want["Reason for State Change"] = at.UTC().Format("Monday 2 January, 2006 15:04:05 MST"), reason
	if !strings.Contains(got, "\""+name+"\"") || !reflect.DeepEqual(actual, want) {
		t.Fatalf("native email data projection differs\ngot: %#v\nwant: %#v", actual, want)
	}
}
