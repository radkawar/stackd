package stackd_test

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type ebMetricRun struct {
	Name, Account, Region string
	Start, PublishAt      time.Time
	OperatorRole          string
	Steps                 []struct {
		At   time.Time
		Call ebTargetRoleObservation
	}
	Queries []ebTargetRoleObservation
}

// Native legacy exporters can place a sample in the preceding minute, including
// different samples from one batch. Compare the scoped capture window's actual
// statistics, not an undocumented exporter phase or datapoint return order.
func ebMetricStatistics(t *testing.T, points []cwtypes.Datapoint) ([5]float64, cwtypes.StandardUnit) {
	t.Helper()
	var totals [5]float64 // sum, count, minimum, maximum, weighted average
	var unit cwtypes.StandardUnit
	for i, point := range points {
		if point.Sum == nil || point.SampleCount == nil || point.Minimum == nil || point.Maximum == nil || point.Average == nil {
			t.Fatalf("metric omitted requested statistics: %+v", point)
		}
		if i == 0 {
			totals[2], totals[3], unit = *point.Minimum, *point.Maximum, point.Unit
		}
		if point.Unit != unit {
			t.Fatalf("metric changed unit within one capture: %s != %s", point.Unit, unit)
		}
		totals[0] += *point.Sum
		totals[1] += *point.SampleCount
		totals[2] = math.Min(totals[2], *point.Minimum)
		totals[3] = math.Max(totals[3], *point.Maximum)
		totals[4] += *point.Average * *point.SampleCount
	}
	if totals[1] != 0 {
		totals[4] /= totals[1]
	}
	return totals, unit
}

func ebMetricQuery(t *testing.T, client *cloudwatch.Client, row ebTargetRoleObservation) {
	t.Helper()
	output, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
	if err != nil {
		t.Fatal(row.Label, err)
	}
	switch got := output.(type) {
	case *cloudwatch.GetMetricStatisticsOutput:
		var input cloudwatch.GetMetricStatisticsInput
		var want cloudwatch.GetMetricStatisticsOutput
		ebTargetRoleDecode(t, row.Input, &input)
		ebTargetRoleDecode(t, row.Output, &want)
		if (len(got.Datapoints) == 0) != (len(want.Datapoints) == 0) {
			t.Fatalf("%s %s %v: datapoint presence changed: got=%+v native=%+v", row.Label, aws.ToString(input.MetricName), input.Dimensions, got.Datapoints, want.Datapoints)
		}
		if len(input.ExtendedStatistics) != 0 {
			if len(got.Datapoints) != len(want.Datapoints) {
				t.Fatalf("%s: percentile datapoint count=%d native=%d", row.Label, len(got.Datapoints), len(want.Datapoints))
			}
			for _, point := range got.Datapoints {
				if !reflect.DeepEqual(point.ExtendedStatistics, want.Datapoints[0].ExtendedStatistics) || point.Unit != want.Datapoints[0].Unit {
					t.Fatalf("%s: percentile=%+v native=%+v", row.Label, point, want.Datapoints[0])
				}
			}
			return
		}
		actual, actualUnit := ebMetricStatistics(t, got.Datapoints)
		expected, expectedUnit := ebMetricStatistics(t, want.Datapoints)
		if strings.HasSuffix(aws.ToString(input.MetricName), "Latency") {
			// The manual clock never advances inside a command or its drain.
			// Native magnitudes remain evidence; local zero defends the clock
			// contract and catches replay latency measured from archive age.
			expected[0], expected[2], expected[3], expected[4] = 0, 0, 0, 0
		}
		for i := range actual {
			if math.Abs(actual[i]-expected[i]) > 1e-9 {
				t.Fatalf("%s %s %v: statistics=%v native=%v", row.Label, aws.ToString(input.MetricName), input.Dimensions, actual, expected)
			}
		}
		if actualUnit != expectedUnit {
			t.Fatalf("%s: unit=%s native=%s", row.Label, actualUnit, expectedUnit)
		}
	case *cloudwatch.GetMetricDataOutput:
		var want cloudwatch.GetMetricDataOutput
		ebTargetRoleDecode(t, row.Output, &want)
		for _, results := range [][]cwtypes.MetricDataResult{got.MetricDataResults, want.MetricDataResults} {
			for i := range results {
				for j := range results[i].Timestamps {
					results[i].Timestamps[j] = results[i].Timestamps[j].UTC()
				}
			}
		}
		if !reflect.DeepEqual(got.MetricDataResults, want.MetricDataResults) || !reflect.DeepEqual(got.Messages, want.Messages) || !reflect.DeepEqual(got.NextToken, want.NextToken) {
			t.Fatalf("%s: query results=%+v native=%+v", row.Label, got, want)
		}
	default:
		t.Fatalf("unexpected metric query %s", row.Operation)
	}
}

func TestEventBridgeNativeMetricsAcrossReopen(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/eventbridge/metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Runs []ebMetricRun }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, run := range fixture.Runs {
			t.Run(backend+"/"+run.Name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "events-metrics.sqlite")
				backends := storage.NewMemory()
				closeDatabase := func() {}
				if backend == "sqlite" {
					backends, closeDatabase = openSQLiteBackends(t, path)
				}
				source := clock.NewManual(run.Start)
				cloud, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
				replay := ebTargetRoleNew(cloud, clients, run.Account, run.Region)
				if run.OperatorRole != "" {
					replay.delegated(t, run.OperatorRole)
				}
				for _, step := range run.Steps {
					t.Run(step.Call.Label, func(t *testing.T) {
						advanceClock(t, source, step.At.Sub(source.Now()))
						trailNativeDrain(t, cloud)
						replay.call(t, step.Call)
						trailNativeDrain(t, cloud)
					})
					if t.Failed() {
						t.FailNow()
					}
				}
				// Reopen with the last completed observations still waiting for
				// their minute boundary, alongside already-published history.
				closeCloud()
				closeDatabase()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, path)
				}
				cloud, clients, _ = startEventDeliveryCloud(t, backends, source)
				advanceClock(t, source, run.PublishAt.Sub(source.Now()))
				client := cloudwatch.New(cloudwatch.Options{Region: run.Region, BaseEndpoint: aws.String(clients.server.URL), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1,
					Credentials: credentials.NewStaticCredentialsProvider(run.Account, "test", "")})
				for range 2 {
					trailNativeDrain(t, cloud)
					for _, query := range run.Queries {
						ebMetricQuery(t, client, query)
					}
					advanceClock(t, source, time.Minute)
				}
			})
		}
	}
}

func TestEventBridgeNativeErrorMetricsAcrossReopen(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/eventbridge/error_metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Account, Region, Bus string
		AdmissionAt          time.Time
		Setup                []ebTargetRoleObservation
		Admission            ebTargetRoleObservation
		Destination          ebTargetRoleObservation
		Receipts             []struct {
			Queue      string
			Body       json.RawMessage
			Attributes map[string]string
		}
		Queries []ebTargetRoleObservation
	}
	ebTargetRoleDecode(t, data, &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "error-metrics.sqlite")
			backends := storage.NewMemory()
			closeDatabase := func() {}
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(fixture.AdmissionAt)
			cloud, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
			replay := ebTargetRoleNew(cloud, clients, fixture.Account, fixture.Region)
			var keyID string
			var rules []string
			for _, row := range fixture.Setup {
				switch row.Operation {
				case "DisableKey":
					var input kms.DisableKeyInput
					ebTargetRoleDecode(t, row.Input, &input)
					input.KeyId = aws.String(keyID)
					row.Input, err = json.Marshal(input)
				case "SetQueueAttributes":
					var input sqs.SetQueueAttributesInput
					ebTargetRoleDecode(t, row.Input, &input)
					if input.Attributes["KmsMasterKeyId"] != "" {
						input.Attributes["KmsMasterKeyId"] = keyID
					}
					row.Input, err = json.Marshal(input)
				case "PutRule":
					var input eventbridge.PutRuleInput
					ebTargetRoleDecode(t, row.Input, &input)
					rules = append(rules, aws.ToString(input.Name))
				}
				if err != nil {
					t.Fatal(err)
				}
				if output := replay.call(t, row); row.Operation == "CreateKey" {
					keyID = aws.ToString(output.(*kms.CreateKeyOutput).KeyMetadata.KeyId)
				}
			}
			admitted := replay.call(t, fixture.Admission).(*eventbridge.PutEventsOutput)
			var admission eventbridge.PutEventsInput
			ebTargetRoleDecode(t, fixture.Admission.Input, &admission)
			ids := make(map[string]string)
			for i, entry := range admission.Entries {
				var detail struct{ Case string }
				ebTargetRoleDecode(t, []byte(aws.ToString(entry.Detail)), &detail)
				ids[detail.Case] = aws.ToString(admitted.Entries[i].EventId)
			}
			trailNativeDrain(t, cloud)
			// Every captured error is terminal even with a retry allowance.
			// Remove the catalog before the completed minute is published:
			// neither the observations nor accepted queue bodies belong to it.
			events := replay.events("")
			for _, rule := range rules {
				if _, err := events.RemoveTargets(t.Context(), &eventbridge.RemoveTargetsInput{Rule: aws.String(rule), EventBusName: &fixture.Bus, Ids: []string{"target"}}); err != nil {
					t.Fatal(err)
				}
				if _, err := events.DeleteRule(t.Context(), &eventbridge.DeleteRuleInput{Name: aws.String(rule), EventBusName: &fixture.Bus}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := events.DeleteEventBus(t.Context(), &eventbridge.DeleteEventBusInput{Name: &fixture.Bus}); err != nil {
				t.Fatal(err)
			}
			closeCloud()
			closeDatabase()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, path)
			}
			cloud, clients, _ = startEventDeliveryCloud(t, backends, source)
			queues := clients.sqs(fixture.Account, "test", "")
			for _, kind := range []string{"dlq", "success", "denied", "encrypted"} {
				name := fixture.Bus + "-" + kind
				out, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: &name})
				if err != nil {
					t.Fatal(err)
				}
				replay.queues[name] = out.QueueUrl
			}
			for _, kind := range []string{"dlq", "success", "denied"} {
				var expected []int
				for i, receipt := range fixture.Receipts {
					if receipt.Queue == kind {
						expected = append(expected, i)
					}
				}
				output, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{
					QueueUrl: replay.queues[fixture.Bus+"-"+kind], MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"}})
				if err != nil || len(output.Messages) != len(expected) {
					t.Fatalf("%s receipts=%+v expected=%d: %v", kind, output, len(expected), err)
				}
				seen := make(map[string]bool)
				for _, message := range output.Messages {
					var got map[string]any
					ebTargetRoleDecode(t, []byte(aws.ToString(message.Body)), &got)
					detail := got["detail"].(map[string]any)
					name := detail["case"].(string)
					if seen[name] || got["id"] != ids[name] || got["time"] != source.Now().UTC().Truncate(time.Second).Format(time.RFC3339) {
						t.Fatalf("lost admitted identity or duplicated receipt: %+v", got)
					}
					seen[name] = true
					matched := false
					for _, i := range expected {
						receipt := fixture.Receipts[i]
						var want map[string]any
						ebTargetRoleDecode(t, receipt.Body, &want)
						if !reflect.DeepEqual(got["detail"], want["detail"]) {
							continue
						}
						matched = true
						if receipt.Attributes["ERROR_MESSAGE"] != "" && aws.ToString(message.MessageAttributes["ERROR_MESSAGE"].StringValue) == "" {
							t.Fatal("DLQ omitted native target diagnosis")
						}
						assertEventDeliveryAttributes(t, message.MessageAttributes, receipt.Attributes)
						got["id"], got["time"] = want["id"], want["time"]
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("native receipt differs: got=%+v want=%+v", got, want)
						}
					}
					if !matched {
						t.Fatalf("unexpected %s receipt: %+v", kind, got)
					}
				}
			}
			var destination sqs.GetQueueAttributesInput
			var destinationWant sqs.GetQueueAttributesOutput
			ebTargetRoleDecode(t, fixture.Destination.Input, &destination)
			ebTargetRoleDecode(t, fixture.Destination.Output, &destinationWant)
			destination.QueueUrl = replay.queues[fixture.Bus+"-encrypted"]
			destinationGot, err := queues.GetQueueAttributes(t.Context(), &destination)
			if err != nil || !reflect.DeepEqual(destinationGot.Attributes, destinationWant.Attributes) {
				t.Fatalf("failed target accepted a message: %+v %v", destinationGot, err)
			}
			// Cross both the retry age and publication boundaries after reopen.
			// A mistaken retryable classification produces extra attempts or
			// late DLQ work rather than silently passing this terminal fixture.
			advanceClock(t, source, 2*time.Minute)
			client := metricsClient(clients, fixture.Account)
			for range 2 {
				trailNativeDrain(t, cloud)
				for _, query := range fixture.Queries {
					ebMetricQuery(t, client, query)
				}
				advanceClock(t, source, time.Minute)
			}
		})
	}
}

func TestRetainedServiceMetricsOutlivePublicTimestampWindow(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "retained-metrics.sqlite"))
			}
			epoch := time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)
			source := clock.NewManual(epoch)
			cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
			replay := ebTargetRoleNew(cloud, clients, "000000000000", "us-east-1")
			replay.call(t, ebTargetRoleObservation{Label: "accept-before-clock-jump", Service: "events", Operation: "PutEvents",
				Input: json.RawMessage(`{"Entries":[{"Source":"stackd.retained","DetailType":"clock","Detail":"{}"}]}`)})
			advanceClock(t, source, 15*24*time.Hour)
			trailNativeDrain(t, cloud)
			client := metricsClient(clients, "000000000000")
			out, err := client.GetMetricStatistics(t.Context(), &cloudwatch.GetMetricStatisticsInput{
				Namespace: aws.String("AWS/Events"), MetricName: aws.String("PutEventsApproximateCallCount"),
				StartTime: aws.Time(epoch.Truncate(time.Hour)), EndTime: aws.Time(epoch.Truncate(time.Hour).Add(time.Hour)),
				Period: aws.Int32(3600), Statistics: []cwtypes.Statistic{cwtypes.StatisticSum, cwtypes.StatisticSampleCount}})
			if err != nil || len(out.Datapoints) != 1 || aws.ToFloat64(out.Datapoints[0].Sum) != 1 || aws.ToFloat64(out.Datapoints[0].SampleCount) != 1 {
				t.Fatalf("retained publication lost or retimestamped its observation: %+v %v", out, err)
			}
			_, err = client.PutMetricData(t.Context(), &cloudwatch.PutMetricDataInput{
				Namespace: aws.String("Custom/Retained"), MetricData: []cwtypes.MetricDatum{{MetricName: aws.String("Caller"), Timestamp: &epoch, Value: aws.Float64(1)}}})
			assertAPIError(t, err, "InvalidParameterValue")
		})
	}
}
