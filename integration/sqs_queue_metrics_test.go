package stackd_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type sqsQueueMetricFixture struct {
	Operations []struct {
		Label, Operation string
		Inputs           json.RawMessage
		Output           struct {
			QueueURL string `json:"QueueUrl"`
			Messages []sqstypes.Message
		}
	}
}

func sqsQueueMetricNative(t *testing.T) sqsQueueMetricFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/sqs/queue_metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	var f sqsQueueMetricFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// Only URLs are rebound. Receipts are taken directly from the current SDK
// response by the caller; no native receipt or partition-order ledger is replayed.
func sqsQueueMetricReplay(t *testing.T, f sqsQueueMetricFixture, client *sqs.Client, replacements *[]string, label string, modify func(any)) any {
	t.Helper()
	for _, row := range f.Operations {
		if row.Label != label {
			continue
		}
		parts := strings.Split(row.Operation, "_")
		for i, part := range parts {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
		input := json.RawMessage(strings.NewReplacer((*replacements)...).Replace(string(row.Inputs)))
		out, err := awstest.CallSDK(t.Context(), client, strings.Join(parts, ""), input, func(in any) {
			if in, ok := in.(*sqs.ReceiveMessageInput); ok {
				in.WaitTimeSeconds = 0
				if len(row.Output.Messages) > 0 {
					in.MaxNumberOfMessages = int32(len(row.Output.Messages))
				}
			}
			if modify != nil {
				modify(in)
			}
		})
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if created, ok := out.(*sqs.CreateQueueOutput); ok {
			*replacements = append(*replacements, row.Output.QueueURL, aws.ToString(created.QueueUrl))
		}
		if received, ok := out.(*sqs.ReceiveMessageOutput); ok {
			if len(received.Messages) != len(row.Output.Messages) {
				t.Fatalf("%s: received %d, native %d", label, len(received.Messages), len(row.Output.Messages))
			}
		}
		return out
	}
	t.Fatalf("missing native operation %s", label)
	return nil
}

func sqsQueueMetricPoints(t *testing.T, client *cloudwatch.Client, queue, metric string, start, end time.Time) []cwtypes.Datapoint {
	t.Helper()
	out, err := client.GetMetricStatistics(t.Context(), &cloudwatch.GetMetricStatisticsInput{
		Namespace: aws.String("AWS/SQS"), MetricName: &metric,
		Dimensions: []cwtypes.Dimension{{Name: aws.String("QueueName"), Value: &queue}},
		StartTime:  &start, EndTime: &end, Period: aws.Int32(60),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticMinimum, cwtypes.StatisticMaximum, cwtypes.StatisticSum, cwtypes.StatisticSampleCount},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.Datapoints
}

func sqsQueueMetricValue(t *testing.T, client *cloudwatch.Client, queue, metric string, minute time.Time, want float64) {
	t.Helper()
	points := sqsQueueMetricPoints(t, client, queue, metric, minute, minute.Add(time.Minute))
	if len(points) != 1 || aws.ToFloat64(points[0].Minimum) != want || aws.ToFloat64(points[0].Maximum) != want {
		t.Fatalf("%s/%s at %s: %+v, want one constant sample %g", queue, metric, minute, points, want)
	}
}

func TestSQSQueueMetricsNativeTransitionsAndRetainedDeadline(t *testing.T) {
	f := sqsQueueMetricNative(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "queue-metrics.sqlite")
			backends, closeDatabase := storage.NewMemory(), func() {}
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			start := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
			source := clock.NewManual(start)
			_, c, closeCloud := startEventDeliveryCloud(t, backends, source)
			client := c.sqs("000000000000", "test", "")
			var replacements []string
			call := func(label string, modify func(any)) any {
				return sqsQueueMetricReplay(t, f, client, &replacements, label, modify)
			}
			urls, names := map[string]*string{}, map[string]string{}
			for _, role := range []string{"state", "delay", "fifo"} {
				urls[role] = call("create-"+role, nil).(*sqs.CreateQueueOutput).QueueUrl
				parts := strings.Split(aws.ToString(urls[role]), "/")
				names[role] = parts[len(parts)-1]
			}
			call("send-state-old", nil)
			call("send-delayed-old-0", nil)
			call("send-delayed-old-1", nil)
			call("fifo-six", nil)
			fifo := call("fifo-hold", nil).(*sqs.ReceiveMessageOutput)
			call("state-hold-old", nil)
			// Reconstruct with queued, delayed and in-flight work halfway to the
			// first deadline. Restart must not reset that deadline to another minute.
			advanceClock(t, source, 30*time.Second)
			closeCloud()
			closeDatabase()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, path)
			}
			cloud, c, _ := startEventDeliveryCloud(t, backends, source)
			client = c.sqs("000000000000", "test", "")
			metrics := metricsClient(c, "000000000000")
			trailNativeDrain(t, cloud)
			if got := sqsQueueMetricPoints(t, metrics, names["state"], "ApproximateNumberOfMessagesNotVisible", start, start.Add(time.Minute)); len(got) != 0 {
				t.Fatalf("restart sampled before retained deadline: %+v", got)
			}
			advanceClock(t, source, 30*time.Second)
			trailNativeDrain(t, cloud)
			check := func(role, metric string, want float64) {
				sqsQueueMetricValue(t, metrics, names[role], metric, source.Now(), want)
			}
			check("state", "ApproximateNumberOfMessagesVisible", 0)
			check("state", "ApproximateNumberOfMessagesNotVisible", 1)
			check("state", "ApproximateAgeOfOldestMessage", 60)
			check("delay", "ApproximateNumberOfMessagesDelayed", 2)
			check("delay", "ApproximateAgeOfOldestMessage", 0)
			check("fifo", "ApproximateNumberOfGroupsWithInflightMessages", 3)
			check("fifo", "ApproximateNumberOfMessagesNotVisible", 6)
			check("fifo", "ApproximateAgeOfOldestMessage", 60)
			call("send-state-young", nil)
			call("send-delay-young", nil)
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			check("state", "ApproximateNumberOfMessagesVisible", 1)
			check("state", "ApproximateAgeOfOldestMessage", 120)
			check("delay", "ApproximateAgeOfOldestMessage", 60)
			// Standard non-noisy work is its own quiet population. No positive
			// native noisy classifier threshold is claimed by this fixture.
			check("state", "ApproximateNumberOfNoisyGroups", 0)
			check("state", "ApproximateNumberOfMessagesVisibleInQuietGroups", 1)
			check("state", "ApproximateNumberOfMessagesNotVisibleInQuietGroups", 1)
			check("state", "ApproximateAgeOfOldestMessageInQuietGroups", 120)
			check("delay", "ApproximateNumberOfMessagesDelayedInQuietGroups", 2)
			// Visibility expiration changes backlog, not the age's origin.
			advanceClock(t, source, 5*time.Minute)
			trailNativeDrain(t, cloud)
			check("state", "ApproximateNumberOfMessagesVisible", 2)
			check("state", "ApproximateNumberOfMessagesNotVisible", 0)
			check("state", "ApproximateAgeOfOldestMessage", 420)
			call("delete-fifo-0", func(in any) {
				batch := in.(*sqs.DeleteMessageBatchInput)
				for i := range batch.Entries {
					batch.Entries[i].ReceiptHandle = fifo.Messages[i].ReceiptHandle
				}
			})
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			check("fifo", "ApproximateNumberOfGroupsWithInflightMessages", 0)
			check("fifo", "ApproximateNumberOfMessagesNotVisible", 0)
			check("fifo", "ApproximateAgeOfOldestMessage", 0)
			check("fifo", "NumberOfDeduplicatedSentMessages", 0)
			if got := sqsQueueMetricPoints(t, metrics, names["fifo"], "SentMessageSize", source.Now(), source.Now().Add(time.Minute)); len(got) != 0 {
				t.Fatalf("FIFO idle size must remain missing: %+v", got)
			}
			advanceClock(t, source, 7*time.Minute)
			trailNativeDrain(t, cloud)
			check("delay", "ApproximateNumberOfMessagesVisible", 3)
			check("delay", "ApproximateNumberOfMessagesDelayed", 0)
			// The younger undelayed message still explains native age after the
			// original delayed work becomes available; SentTimestamp does not.
			check("delay", "ApproximateAgeOfOldestMessage", 840)
			call("purge-delay", nil)
			call("send-solo-delay120", nil)
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			check("delay", "ApproximateNumberOfMessagesDelayed", 1)
			check("delay", "ApproximateAgeOfOldestMessage", 0)
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			check("delay", "ApproximateNumberOfMessagesVisible", 1)
			check("delay", "ApproximateNumberOfMessagesDelayed", 0)
			check("delay", "ApproximateAgeOfOldestMessage", 0)
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			check("delay", "ApproximateAgeOfOldestMessage", 60)
		})
	}
}

func TestSQSQueueMetricsActivityExpiryDeletionAndCurrentSnapshot(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "activity.sqlite"))
			}
			start := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
			source := clock.NewManual(start)
			cloud, c, _ := startEventDeliveryCloud(t, backends, source)
			client, metrics := c.sqs(eventDeliveryAccount, "test", ""), metricsClient(c, eventDeliveryAccount)
			name := "metric-activity"
			created, err := client.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: &name})
			if err != nil {
				t.Fatal(err)
			}
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"sqs:GetQueueAttributes","Resource":"arn:aws:sqs:us-east-1:%s:%s"}]}`, eventDeliveryAccount, name)
			if _, err := client.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: created.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			for _, metric := range []string{"NumberOfMessagesSent", "NumberOfMessagesReceived", "NumberOfMessagesDeleted", "NumberOfEmptyReceives"} {
				sqsQueueMetricValue(t, metrics, name, metric, source.Now(), 0)
			}
			for _, metric := range []string{"SentMessageSize", "NumberOfDeduplicatedSentMessages"} {
				if got := sqsQueueMetricPoints(t, metrics, name, metric, start, source.Now().Add(time.Minute)); len(got) != 0 {
					t.Fatalf("idle standard %s must remain missing: %+v", metric, got)
				}
			}
			// Six-hour empty expiry is AWS-documented, not a newly captured
			// six-hour native experiment (source retained in fixture context).
			advanceClock(t, source, 6*time.Hour-time.Minute)
			trailNativeDrain(t, cloud)
			if got := sqsQueueMetricPoints(t, metrics, name, "ApproximateNumberOfMessagesVisible", start.Add(2*time.Minute), source.Now().Add(time.Minute)); len(got) != 0 {
				t.Fatalf("expired empty queue fabricated skipped/expired samples: %+v", got)
			}
			_, err = client.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: created.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameAll}})
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDenied" {
				t.Fatalf("explicit-deny root request: %v", err)
			}
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			sqsQueueMetricValue(t, metrics, name, "ApproximateNumberOfMessagesVisible", source.Now(), 0)
			if _, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: created.QueueUrl, MessageBody: aws.String("backlog")}); err != nil {
				t.Fatal(err)
			}
			jumpStart := source.Now()
			advanceClock(t, source, 2*time.Hour)
			trailNativeDrain(t, cloud)
			points := sqsQueueMetricPoints(t, metrics, name, "ApproximateNumberOfMessagesVisible", jumpStart.Add(time.Minute), source.Now().Add(time.Minute))
			if len(points) != 1 || !points[0].Timestamp.Equal(source.Now()) || aws.ToFloat64(points[0].Maximum) != 1 {
				t.Fatalf("jump must publish only current backlog: %+v", points)
			}
			sqsQueueMetricValue(t, metrics, name, "ApproximateAgeOfOldestMessage", source.Now(), 7200)
			deletedAt := source.Now()
			if _, err := client.DeleteQueue(t.Context(), &sqs.DeleteQueueInput{QueueUrl: created.QueueUrl}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 2*time.Minute)
			trailNativeDrain(t, cloud)
			if got := sqsQueueMetricPoints(t, metrics, name, "ApproximateNumberOfMessagesVisible", deletedAt.Add(time.Minute), source.Now().Add(time.Minute)); len(got) != 0 {
				t.Fatalf("deleted queue sampled again: %+v", got)
			}
			sqsQueueMetricValue(t, metrics, name, "ApproximateNumberOfMessagesVisible", deletedAt, 1)
		})
	}
}

func TestSQSQueueMetricsNativePoisonAndDLQEntryAge(t *testing.T) {
	f := sqsQueueMetricNative(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "age.sqlite"))
			}
			start := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
			source := clock.NewManual(start)
			cloud, c, _ := startEventDeliveryCloud(t, backends, source)
			client, metrics := c.sqs("000000000000", "test", ""), metricsClient(c, "000000000000")
			var replacements []string
			call := func(label string, modify func(any)) any {
				return sqsQueueMetricReplay(t, f, client, &replacements, label, modify)
			}
			names := map[string]string{}
			for _, role := range []string{"poison", "source", "dead"} {
				url := aws.ToString(call("create-"+role, nil).(*sqs.CreateQueueOutput).QueueUrl)
				parts := strings.Split(url, "/")
				names[role] = parts[len(parts)-1]
			}
			call("set-three-receive-redrive", nil)
			call("send-three-receive-old", nil)
			call("send-poison-old", nil)
			advanceClock(t, source, 3*time.Minute)
			trailNativeDrain(t, cloud)
			for i := 1; i <= 3; i++ {
				for _, role := range []string{"source", "poison"} {
					out := call(fmt.Sprintf("%s-receive-%d", role, i), nil).(*sqs.ReceiveMessageOutput)
					if out.Messages[0].Attributes["ApproximateReceiveCount"] != fmt.Sprint(i) {
						t.Fatalf("%s delivery %d: %+v", role, i, out.Messages)
					}
					call(fmt.Sprintf("%s-release-%d", role, i), func(in any) { in.(*sqs.ChangeMessageVisibilityInput).ReceiptHandle = out.Messages[0].ReceiptHandle })
				}
				if i == 2 {
					call("send-poison-young", nil)
				}
			}
			// The controlled native follow-up also kept the older age with
			// younger work present before delivery three. Delivery four in the
			// original capture switched the age to younger work.
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			sqsQueueMetricValue(t, metrics, names["poison"], "ApproximateAgeOfOldestMessage", source.Now(), 240)
			call("trigger-three-receive-automatic-transfer", nil)
			transferredAt := source.Now()
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			sqsQueueMetricValue(t, metrics, names["source"], "ApproximateNumberOfMessagesVisible", source.Now(), 0)
			sqsQueueMetricValue(t, metrics, names["dead"], "ApproximateNumberOfMessagesVisible", source.Now(), 1)
			sqsQueueMetricValue(t, metrics, names["dead"], "ApproximateAgeOfOldestMessage", source.Now(), 60)
			fourth := call("poison-fourth-receive-younger-present", nil).(*sqs.ReceiveMessageOutput)
			call("poison-fourth-release-poison-old", func(in any) { in.(*sqs.ChangeMessageVisibilityInput).ReceiptHandle = fourth.Messages[0].ReceiptHandle })
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			sqsQueueMetricValue(t, metrics, names["poison"], "ApproximateNumberOfMessagesVisible", source.Now(), 2)
			sqsQueueMetricValue(t, metrics, names["poison"], "ApproximateAgeOfOldestMessage", source.Now(), 180)
			dead := call("dead-inspect-original-sent-timestamp", nil).(*sqs.ReceiveMessageOutput)
			if dead.Messages[0].Attributes["SentTimestamp"] != fmt.Sprint(start.UnixMilli()) || dead.Messages[0].Attributes["ApproximateReceiveCount"] != "4" {
				t.Fatalf("standard DLQ must retain wire sent timestamp and cumulative receives: %+v", dead.Messages)
			}
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			// Four cumulative receives must not poison this first DLQ delivery.
			// Held DLQ work ages from entry, not source send or first DLQ receive.
			sqsQueueMetricValue(t, metrics, names["dead"], "ApproximateAgeOfOldestMessage", source.Now(), source.Now().Sub(transferredAt).Seconds())
		})
	}
}

func TestSQSQueueMetricsDriveBacklogAlarmWithoutCustomerPublication(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "alarm.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC))
			cloud, c, _ := startEventDeliveryCloud(t, backends, source)
			client, metrics := c.sqs(eventDeliveryAccount, "test", ""), metricsClient(c, eventDeliveryAccount)
			name := "sqs-backlog-alarm"
			queue, err := client.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: &name})
			if err != nil {
				t.Fatal(err)
			}
			_, err = metrics.PutMetricAlarm(t.Context(), &cloudwatch.PutMetricAlarmInput{
				AlarmName: &name, Namespace: aws.String("AWS/SQS"), MetricName: aws.String("ApproximateNumberOfMessagesVisible"),
				Dimensions: []cwtypes.Dimension{{Name: aws.String("QueueName"), Value: &name}},
				Period:     aws.Int32(60), EvaluationPeriods: aws.Int32(1), Statistic: cwtypes.StatisticMaximum,
				Threshold: aws.Float64(0), ComparisonOperator: cwtypes.ComparisonOperatorGreaterThanThreshold, TreatMissingData: aws.String("notBreaching"),
			})
			if err != nil {
				t.Fatal(err)
			}
			state := func(want cwtypes.StateValue) {
				t.Helper()
				out, err := metrics.DescribeAlarms(t.Context(), &cloudwatch.DescribeAlarmsInput{AlarmNames: []string{name}})
				if err != nil || len(out.MetricAlarms) != 1 || out.MetricAlarms[0].StateValue != want {
					t.Fatalf("backlog alarm want %s: %+v %v", want, out, err)
				}
			}
			for range 3 {
				advanceClock(t, source, time.Minute)
				trailNativeDrain(t, cloud)
			}
			state(cwtypes.StateValueOk)
			if _, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("alarm-backlog")}); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				advanceClock(t, source, time.Minute)
				trailNativeDrain(t, cloud)
			}
			state(cwtypes.StateValueAlarm)
			if _, err := client.PurgeQueue(t.Context(), &sqs.PurgeQueueInput{QueueUrl: queue.QueueUrl}); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				advanceClock(t, source, time.Minute)
				trailNativeDrain(t, cloud)
			}
			state(cwtypes.StateValueOk)
		})
	}
}
