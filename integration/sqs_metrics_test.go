package stackd_test

import (
	"encoding/json"
	"errors"
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

type sqsCounterFixture struct {
	Operations []struct {
		Label, Operation string
		Inputs           json.RawMessage
		Output           struct {
			QueueURL   string `json:"QueueUrl"`
			Messages   []sqstypes.Message
			Successful []sqstypes.SendMessageBatchResultEntry
			Failed     []sqstypes.BatchResultErrorEntry
		}
		Error struct{ Error struct{ Code string } }
	}
	Polls []struct {
		Metrics []struct {
			Input  cloudwatch.GetMetricStatisticsInput
			Output cloudwatch.GetMetricStatisticsOutput
		}
	}
	Window struct{ Start, End time.Time } `json:"metric_window"`
}

func TestSQSNativeCountersRetainRequestSamplesAcrossReopen(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/sqs/metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture sqsCounterFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sqs-metrics.sqlite")
			backends := storage.NewMemory()
			closeDatabase := func() {}
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(fixture.Window.Start)
			_, c, closeCloud := startEventDeliveryCloud(t, backends, source)
			client := c.sqs("test", "test", "")
			var replacements, urls []string
			for _, row := range fixture.Operations {
				if row.Operation == "get_caller_identity" || row.Operation == "list_metrics" || strings.HasPrefix(row.Label, "cleanup-") {
					continue
				}
				parts := strings.Split(row.Operation, "_")
				for i, part := range parts {
					parts[i] = strings.ToUpper(part[:1]) + part[1:]
				}
				input := json.RawMessage(strings.NewReplacer(replacements...).Replace(string(row.Inputs)))
				result, err := awstest.CallSDK(t.Context(), client, strings.Join(parts, ""), input, func(in any) {
					// Native standard short polls sampled smaller batches than requested.
					// Reproduce those batch sizes, not AWS's partition selection/order.
					if in, ok := in.(*sqs.ReceiveMessageInput); ok && len(row.Output.Messages) > 0 {
						in.MaxNumberOfMessages = int32(len(row.Output.Messages))
					}
				})
				if row.Error.Error.Code != "" {
					var apiErr smithy.APIError
					if !errors.As(err, &apiErr) || apiErr.ErrorCode() != row.Error.Error.Code {
						t.Fatalf("%s: got %v, native %s", row.Label, err, row.Error.Error.Code)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s: %v", row.Label, err)
				}
				switch out := result.(type) {
				case *sqs.CreateQueueOutput:
					replacements = append(replacements, row.Output.QueueURL, aws.ToString(out.QueueUrl))
					urls = append(urls, aws.ToString(out.QueueUrl))
				case *sqs.ReceiveMessageOutput:
					if len(out.Messages) != len(row.Output.Messages) {
						t.Fatalf("%s: returned %d messages, native %d", row.Label, len(out.Messages), len(row.Output.Messages))
					}
					// Keep each actual receipt for later native delete/repeat operations.
					// Standard delivery order and opaque receipt spelling are not pinned.
					for i, message := range out.Messages {
						replacements = append(replacements, aws.ToString(row.Output.Messages[i].ReceiptHandle), aws.ToString(message.ReceiptHandle))
					}
				case *sqs.SendMessageBatchOutput:
					if len(out.Successful) != len(row.Output.Successful) || len(out.Failed) != len(row.Output.Failed) {
						t.Fatalf("%s: batch success/failure differs: %+v", row.Label, out)
					}
				case *sqs.DeleteMessageBatchOutput:
					if len(out.Successful) != len(row.Output.Successful) || len(out.Failed) != len(row.Output.Failed) {
						t.Fatalf("%s: batch success/failure differs: %+v", row.Label, out)
					}
				}
			}
			// Delete queues and reopen before the completed-minute publication.
			// This exercises retained pending counts, not merely CloudWatch history.
			for _, url := range urls {
				if _, err := client.DeleteQueue(t.Context(), &sqs.DeleteQueueInput{QueueUrl: &url}); err != nil {
					t.Fatal(err)
				}
			}
			closeCloud()
			closeDatabase()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, path)
			}
			cloud, c, _ := startEventDeliveryCloud(t, backends, source)
			advanceClock(t, source, fixture.Window.End.Sub(source.Now()))
			trailNativeDrain(t, cloud)
			metrics := metricsClient(c, "test")
			for _, native := range fixture.Polls[len(fixture.Polls)-1].Metrics {
				out, err := metrics.GetMetricStatistics(t.Context(), &native.Input)
				if err != nil || len(out.Datapoints) != 1 {
					t.Fatalf("%s after queue deletion/reopen: %+v %v", aws.ToString(native.Input.MetricName), out, err)
				}
				want, got := native.Output.Datapoints[0], out.Datapoints[0]
				values := func(p cwtypes.Datapoint) [5]float64 {
					return [5]float64{aws.ToFloat64(p.Sum), aws.ToFloat64(p.SampleCount), aws.ToFloat64(p.Minimum), aws.ToFloat64(p.Maximum), aws.ToFloat64(p.Average)}
				}
				if values(got) != values(want) || got.Unit != want.Unit || !got.Timestamp.Equal(*want.Timestamp) {
					t.Fatalf("%s/%s: got statistics %v at %v (%s), native %v at %v (%s)", aws.ToString(native.Input.Dimensions[0].Value), aws.ToString(native.Input.MetricName), values(got), got.Timestamp, got.Unit, values(want), want.Timestamp, want.Unit)
				}
			}
		})
	}
}
