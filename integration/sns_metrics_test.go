package stackd_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type snsMetricDelivery struct {
	Queue            string
	PublicationLabel string `json:"publication_label"`
	MessageID        string `json:"message_id"`
	Envelope         snsMetricNotification
}

type snsMetricNotification struct {
	snsAdmissionNotification
	SignatureVersion string
}

type snsMetricFixture struct {
	snsAdmissionFixture
	Owned struct {
		Queues map[string]string
	} `json:"owned_resources"`
	Deliveries []snsMetricDelivery
	Boundary   struct {
		Bucket     time.Time `json:"bucket_start_utc"`
		Deliveries []snsMetricDelivery
	} `json:"boundary_capture"`
	Windows []struct {
		Label string
		Start time.Time `json:"bucket_start"`
		End   time.Time `json:"bucket_end"`
	}
	LatestMetricLabel string          `json:"latest_metric_source_label"`
	LatestMetricData  json.RawMessage `json:"latest_metric_data"`
	ReceiptSummary    map[string]struct {
		Labels []string `json:"publication_labels"`
	} `json:"receipt_summary"`
	SupplementalMetricQueries []awsNativeObservation `json:"supplemental_metric_queries"`
	SDKErrorProjection        *struct {
		Code, Operation string
		Input           json.RawMessage
		HTTPStatus      int    `json:"http_status"`
		SDKErrorType    string `json:"sdk_error_type"`
	} `json:"sdk_error_projection"`
}

func TestSNSNativeMetrics(t *testing.T) {
	replaySNSMetrics(t, "metrics")
}

func TestSNSNativeMetricOutcomes(t *testing.T) {
	replaySNSMetrics(t, "metric_outcomes")
}

func TestSNSNativeAttributeFilterMetrics(t *testing.T) {
	replaySNSMetrics(t, "metric_filter_attributes")
}

func replaySNSMetrics(t *testing.T, filename string) {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/sns/" + filename + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture snsMetricFixture
	awsDecodeJSON(t, data, &fixture)
	// The supplemental boundary capture was appended after cleanup in the JSON,
	// although its publications occurred before the final metric poll.
	sort.SliceStable(fixture.Observations, func(i, j int) bool { return fixture.Observations[i].Started < fixture.Observations[j].Started })
	metricRow := snsControlRow(t, fixture.snsAdmissionFixture, fixture.LatestMetricLabel)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "sns-metrics.sqlite")
			var closeDB func()
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(time.UnixMilli(fixture.Observations[0].Started).UTC())
			cloud, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
			topics, queues := admissionSNSClient(clients, fixture.Account, fixture.Region), clients.sqs(fixture.Account, "test", "")
			metrics := metricsClient(clients, fixture.Account)
			urls, queueNames, subscriptions := map[string]string{}, map[string]string{}, map[string]string{}
			seen := map[string][]string{}
			nativeDeliveries := append(append([]snsMetricDelivery(nil), fixture.Deliveries...), fixture.Boundary.Deliveries...)
			kinds := make([]string, 0, len(fixture.Owned.Queues))
			for kind := range fixture.Owned.Queues {
				kinds = append(kinds, kind)
				seen[kind] = []string{}
			}
			sort.Strings(kinds)
			query := func() cloudwatch.GetMetricDataInput {
				var input cloudwatch.GetMetricDataInput
				awsDecodeJSON(t, metricRow.Input, &input)
				return input
			}
			readMetrics := func(client *cloudwatch.Client, input cloudwatch.GetMetricDataInput) *cloudwatch.GetMetricDataOutput {
				out, err := client.GetMetricData(t.Context(), &input)
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			assertEmpty := func(out *cloudwatch.GetMetricDataOutput) {
				t.Helper()
				for _, result := range out.MetricDataResults {
					if len(result.Values) != 0 || len(result.Timestamps) != 0 {
						t.Fatalf("unexpected SNS metric samples: %+v", result)
					}
				}
			}
			settle := func() {
				if out, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || out.More {
					t.Fatalf("SNS metric/delivery jobs did not settle: %+v, %v", out, err)
				}
			}
			prepare := func(input any) {
				switch in := input.(type) {
				case *sqs.SetQueueAttributesInput:
					in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
				case *sqs.GetQueueAttributesInput:
					in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
				case *sqs.DeleteQueueInput:
					in.QueueUrl = aws.String(urls[aws.ToString(in.QueueUrl)])
				case *sns.GetSubscriptionAttributesInput:
					in.SubscriptionArn = aws.String(subscriptions[aws.ToString(in.SubscriptionArn)])
				case *sns.UnsubscribeInput:
					in.SubscriptionArn = aws.String(subscriptions[aws.ToString(in.SubscriptionArn)])
				}
			}
			for _, row := range fixture.Observations {
				switch row.Operation {
				case "create-topic", "create-queue", "set-queue-attributes", "get-queue-attributes", "subscribe", "get-subscription-attributes", "publish", "publish-batch", "unsubscribe", "delete-topic", "get-topic-attributes", "delete-queue":
				case "receive-message":
				case "get-metric-data":
					if row.Label != fixture.LatestMetricLabel {
						continue
					}
				default:
					// Native receives are evidence, not portable receipt handles. The
					// real SDK consumer below receives and deletes each publication.
					continue
				}
				at := time.UnixMilli(row.Started).UTC()
				if err := source.Advance(at.Sub(source.Now())); err != nil {
					t.Fatal(err)
				}
				settle()
				if row.Operation == "get-metric-data" {
					assertMetricData(t, readMetrics(metrics, query()), fixture.LatestMetricData)
					continue
				}
				if row.Operation == "receive-message" {
					// Publications were already drained and correlated below. Repeat
					// the captured receive windows to catch delayed rejected entries
					// or duplicate deliveries, without asserting permanent absence.
					var input sqs.ReceiveMessageInput
					awsDecodeJSON(t, row.Input, &input)
					queueURL := urls[aws.ToString(input.QueueUrl)]
					if messages := snsAdmissionReceive(t, cloud, queues, &queueURL); len(messages) != 0 {
						t.Fatalf("%s: unexpected delayed SNS deliveries: %+v", row.Label, messages)
					}
					continue
				}
				var client any = topics
				if row.Service == "sqs" {
					client = queues
				}
				out := snsControlReplay(t, client, row, prepare)
				// Response IDs are correlated, not compared to random native IDs.
				// Topic/queue names, ARN scopes, policies and message bytes stay native.
				published := map[string]string{}
				switch row.Operation {
				case "create-topic":
					var input sns.CreateTopicInput
					awsDecodeJSON(t, row.Input, &input)
					want := "arn:aws:sns:" + fixture.Region + ":" + fixture.Account + ":" + aws.ToString(input.Name)
					if aws.ToString(out.(*sns.CreateTopicOutput).TopicArn) != want {
						t.Fatalf("topic scope differs from native %s", want)
					}
				case "create-queue":
					var native sqs.CreateQueueOutput
					var input sqs.CreateQueueInput
					awsDecodeJSON(t, row.Result.Output, &native)
					awsDecodeJSON(t, row.Input, &input)
					urls[aws.ToString(native.QueueUrl)] = aws.ToString(out.(*sqs.CreateQueueOutput).QueueUrl)
					queueNames[aws.ToString(native.QueueUrl)] = aws.ToString(input.QueueName)
				case "subscribe":
					var native sns.SubscribeOutput
					awsDecodeJSON(t, row.Result.Output, &native)
					subscriptions[aws.ToString(native.SubscriptionArn)] = aws.ToString(out.(*sns.SubscribeOutput).SubscriptionArn)
				case "publish":
					if row.Result.Code == "Success" {
						var native sns.PublishOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						published[aws.ToString(out.(*sns.PublishOutput).MessageId)] = aws.ToString(native.MessageId)
					}
				case "publish-batch":
					if row.Result.Code != "Success" {
						break
					}
					var native sns.PublishBatchOutput
					awsDecodeJSON(t, row.Result.Output, &native)
					actual := out.(*sns.PublishBatchOutput)
					if len(actual.Failed) != len(native.Failed) || len(actual.Successful) != len(native.Successful) {
						t.Fatalf("%s: batch admission differs from native", row.Label)
					}
					type failure struct {
						Code        string
						SenderFault bool
					}
					gotFailed, wantFailed := map[string]failure{}, map[string]failure{}
					for _, entry := range actual.Failed {
						gotFailed[aws.ToString(entry.Id)] = failure{aws.ToString(entry.Code), entry.SenderFault}
					}
					for _, entry := range native.Failed {
						wantFailed[aws.ToString(entry.Id)] = failure{aws.ToString(entry.Code), entry.SenderFault}
					}
					if len(actual.Failed) != len(gotFailed) || !maps.Equal(gotFailed, wantFailed) {
						t.Fatalf("%s: batch entry failures: got %v, native %v", row.Label, gotFailed, wantFailed)
					}
					remaining := map[string]string{}
					for _, entry := range native.Successful {
						remaining[aws.ToString(entry.Id)] = aws.ToString(entry.MessageId)
					}
					for _, entry := range actual.Successful {
						id := aws.ToString(entry.Id)
						nativeID, ok := remaining[id]
						if !ok {
							t.Fatalf("%s: unexpected or duplicate batch success %s", row.Label, id)
						}
						published[aws.ToString(entry.MessageId)] = nativeID
						delete(remaining, id)
					}
					if len(remaining) != 0 {
						t.Fatalf("%s: native accepted entries missing: %v", row.Label, remaining)
					}
				}
				if row.Operation != "publish" && row.Operation != "publish-batch" {
					continue
				}
				// Drain before advancing time: successful delivery and filter samples
				// belong to this native publication minute, not the next API call.
				for _, kind := range kinds {
					expected := map[string]snsMetricDelivery{}
					for _, delivery := range nativeDeliveries {
						if delivery.Queue != kind {
							continue
						}
						for _, nativeID := range published {
							if delivery.MessageID == nativeID {
								expected[nativeID] = delivery
							}
						}
					}
					queueURL := urls[fixture.Owned.Queues[kind]]
					for _, message := range snsAdmissionReceive(t, cloud, queues, &queueURL) {
						var envelope snsMetricNotification
						awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &envelope)
						nativeID := published[envelope.MessageId]
						want, ok := expected[nativeID]
						if !ok {
							t.Fatalf("%s/%s: unexpected or duplicate SNS correlation %s", row.Label, kind, envelope.MessageId)
						}
						if envelope.SignatureVersion != want.Envelope.SignatureVersion {
							t.Fatalf("%s/%s: signature version differs from native", row.Label, kind)
						}
						var signed map[string]any
						awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &signed)
						endpoint := aws.ToString(topics.Options().BaseEndpoint)
						snsVerifySignature(t, signed, endpoint, endpoint)
						envelope.MessageId = nativeID
						if !reflect.DeepEqual(envelope.snsAdmissionNotification, want.Envelope.snsAdmissionNotification) {
							t.Fatalf("%s/%s: SNS body, Subject, attributes or topic differs from native", row.Label, kind)
						}
						delete(expected, nativeID)
						if fixture.Boundary.Bucket.IsZero() || at.Before(fixture.Boundary.Bucket) {
							seen[kind] = append(seen[kind], want.PublicationLabel)
						}
					}
					if len(expected) != 0 {
						t.Fatalf("%s/%s: %d native deliveries missing", row.Label, kind, len(expected))
					}
				}
				if row.Label == "single-body-subject-attributes" {
					minute, end := at.Truncate(time.Minute), at.Truncate(time.Minute).Add(time.Minute)
					pending := query()
					pending.StartTime, pending.EndTime = &minute, &end
					assertEmpty(readMetrics(metrics, pending))
					if backend == "sqlite" {
						// All seven receipts have completed, but the minute's samples
						// are still pending. Restart before the minute boundary.
						closeCloud()
						closeDB()
						backends, _ = openSQLiteBackends(t, path)
						cloud, clients, _ = startEventDeliveryCloud(t, backends, source)
						topics, queues = admissionSNSClient(clients, fixture.Account, fixture.Region), clients.sqs(fixture.Account, "test", "")
						metrics = metricsClient(clients, fixture.Account)
						for nativeURL, name := range queueNames {
							queue, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String(name)})
							if err != nil {
								t.Fatal(err)
							}
							urls[nativeURL] = aws.ToString(queue.QueueUrl)
						}
						settle()
						assertEmpty(readMetrics(metrics, pending))
					}
				}
			}
			for kind, summary := range fixture.ReceiptSummary {
				sort.Strings(seen[kind])
				if !reflect.DeepEqual(seen[kind], summary.Labels) {
					t.Fatalf("%s original workload receipts: %v; native %v (boundary excluded)", kind, seen[kind], summary.Labels)
				}
			}
			// Consumed groups cannot be republished by another scheduler pass, nor
			// may topic deletion erase historical metrics. Compare every captured
			// timestamp/value, including missing series and zero-valued samples.
			if err := source.Advance(time.Minute); err != nil {
				t.Fatal(err)
			}
			settle()
			assertMetricData(t, readMetrics(metrics, query()), fixture.LatestMetricData)
			for _, row := range fixture.SupplementalMetricQueries {
				t.Run(row.Label, func(t *testing.T) {
					out := snsControlReplay(t, metrics, row)
					assertMetricData(t, out.(*cloudwatch.GetMetricDataOutput), row.Result.Output)
				})
			}
			if projection := fixture.SDKErrorProjection; projection != nil {
				// This is the actual Go SDK projection of the deleted native
				// queue, not a relaxation of the CLI code/HTTP cleanup checks.
				_, err := awstest.CallSDK(t.Context(), queues, projection.Operation, projection.Input, prepare)
				row := awsNativeObservation{Label: "native-sdk-deleted-queue"}
				row.Result.Code, row.Result.HTTPStatus = projection.Code, projection.HTTPStatus
				awsNativeResult(t, row, err)
				var missing *sqstypes.QueueDoesNotExist
				if !errors.As(err, &missing) || fmt.Sprintf("%T", missing) != projection.SDKErrorType {
					t.Fatalf("deleted queue: expected native modeled %s, got %T: %v", projection.SDKErrorType, err, err)
				}
				if missing.ErrorCode() != projection.Code {
					t.Fatalf("deleted queue: modeled error code %s; native %s", missing.ErrorCode(), projection.Code)
				}
			}
			for _, window := range fixture.Windows {
				if window.Label != "idle-no-publication-minute" {
					continue
				}
				input := query()
				input.StartTime, input.EndTime = &window.Start, &window.End
				assertEmpty(readMetrics(metrics, input))
			}
			for _, scope := range []string{"account", "region", "topic", "namespace", "no-dimensions"} {
				t.Logf("checking empty SNS metric scope: %s", scope)
				input, scoped := query(), metrics
				switch scope {
				case "account":
					scoped = metricsClient(clients, "444444444444")
				case "region":
					scoped = cloudwatch.New(metrics.Options(), func(o *cloudwatch.Options) { o.Region = "us-west-2" })
				default:
					for i := range input.MetricDataQueries {
						metric := input.MetricDataQueries[i].MetricStat.Metric
						switch scope {
						case "topic":
							metric.Dimensions[0].Value = aws.String(aws.ToString(metric.Dimensions[0].Value) + "-other")
						case "namespace":
							metric.Namespace = aws.String("Other/SNS")
						case "no-dimensions":
							metric.Dimensions = nil
						}
					}
				}
				assertEmpty(readMetrics(scoped, input))
			}
		})
	}
}
