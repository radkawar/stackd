package stackd_test

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/storage"
	lambdastorage "stackd/storage/lambda"
)

type lambdaTargetsMetric struct {
	Sum         *float64 `json:"sum"`
	SampleCount *float64 `json:"sample_count"`
}

type lambdaTargetsCapture struct {
	lambdaEventsFixture
	Deliveries []struct {
		Label string         `json:"source_label"`
		Body  map[string]any `json:"body_decoded"`
	} `json:"deliveries"`
	Invocations []struct {
		Label   string          `json:"label"`
		Payload json.RawMessage `json:"payload"`
	} `json:"invocations"`
}

// lambdaFixture preserves the capture verbatim. Only the captured account is
// relocated here; customer ZIPs and payloads are never rewritten.
func lambdaTargetsFixture[T any](t *testing.T, name string) T {
	t.Helper()
	raw := lambdaFixture[json.RawMessage](t, name)
	var fixture T
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(raw), "000000000000", "000000000000")), &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func lambdaTargetsCloud(t *testing.T, backend string) (*lambdaEventsCloud, *clock.Manual) {
	t.Helper()
	backends := storage.NewMemory()
	if backend == "sqlite" {
		var closeDB func()
		backends, closeDB = openSQLiteBackends(t, filepath.Join(t.TempDir(), "lambda-targets.sqlite"))
		t.Cleanup(closeDB)
	}
	source := clock.NewManual(time.Date(2026, 9, 14, 15, 0, 0, 123456789, time.UTC))
	return lambdaEventsConnect(t, backends, source), source
}

func lambdaTargetsPolicy(t *testing.T, c *lambdaEventsCloud, f lambdaEventsFixture, label string) {
	t.Helper()
	if _, err := (cloudClients{c.server}).iam("test", "test", "").PutRolePolicy(t.Context(), lambdaEventsInput[iam.PutRolePolicyInput](t, f, label)); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
}

func lambdaTargetsCreate(t *testing.T, c *lambdaEventsCloud, f lambdaEventsFixture, label string, queueURL *string) string {
	t.Helper()
	input := lambdaEventsInput[awslambda.CreateFunctionInput](t, f, label)
	if queueURL != nil {
		input.Environment.Variables["QUEUE_URL"] = strings.Replace(aws.ToString(queueURL), "127.0.0.1", "host.docker.internal", 1)
	}
	out, err := c.lambda.CreateFunction(t.Context(), input)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: input.FunctionName}, time.Minute); err != nil {
		t.Fatal(err)
	}
	return aws.ToString(out.FunctionArn)
}

func lambdaTargetsConfig(t *testing.T, c *lambdaEventsCloud, source *clock.Manual, f lambdaEventsFixture, label string) {
	t.Helper()
	if _, err := c.lambda.PutFunctionEventInvokeConfig(t.Context(), lambdaEventsInput[awslambda.PutFunctionEventInvokeConfigInput](t, f, label)); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	advanceClock(t, source, 2*time.Minute)
	if _, err := c.cloud.RunDueJobs(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
}

func lambdaTargetsInvoke(t *testing.T, c *lambdaEventsCloud, f lambdaEventsFixture, label string, payload json.RawMessage) string {
	t.Helper()
	input := lambdaEventsInput[awslambda.InvokeInput](t, f, label)
	input.Payload = payload
	out, err := c.lambda.Invoke(t.Context(), input)
	if err != nil || out.StatusCode != 202 || len(out.Payload) != 0 || out.FunctionError != nil {
		t.Fatalf("%s async acceptance: %+v, %v", label, out, err)
	}
	id, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
	if !ok || id == "" {
		t.Fatal("asynchronous acceptance lacks a request ID")
	}
	return id
}

// This is only a completion barrier. Assertions below consume SDK effects and
// real runtime witnesses, rather than interpreting retained scheduler state as
// evidence of an executed customer handler.
func lambdaTargetsIdle(t *testing.T, c *lambdaEventsCloud) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for {
		if _, err := c.cloud.RunDueJobs(ctx, 100); err != nil {
			t.Fatal(err)
		}
		idle := false
		if err := c.repository.View(ctx, func(r lambdastorage.Reader) error {
			_, queued, err := r.NextInvocation()
			if err != nil {
				return err
			}
			inflight, err := r.InFlightInvocations()
			if err != nil {
				return err
			}
			_, delivering, err := r.NextOutcomeDelivery()
			idle = !queued && len(inflight) == 0 && !delivering
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if idle {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("real Lambda work did not complete", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func lambdaTargetsJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func lambdaTargetsRecord(t *testing.T, got, native map[string]any, requestID string, completed time.Time) {
	t.Helper()
	// Replace only run identities and service time in the complete native
	// document. The original runtime's entire result, including error payload,
	// remains the oracle; no locally constructed expected response is used.
	oldID := native["requestContext"].(map[string]any)["requestId"].(string)
	encoded, err := json.Marshal(native)
	if err != nil {
		t.Fatal(err)
	}
	want := lambdaTargetsJSON(t, []byte(strings.ReplaceAll(string(encoded), oldID, requestID)))
	stamp, ok := got["timestamp"].(string)
	if !ok || stamp != completed.UTC().Format("2006-01-02T15:04:05.000Z") {
		t.Fatalf("destination millisecond completion timestamp = %#v, want %s", got["timestamp"], completed)
	}
	want["timestamp"] = stamp
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("full destination record differs from native:\ngot %#v\nwant %#v", got, want)
	}
}

func lambdaTargetsMetrics(t *testing.T, c *lambdaEventsCloud, source *clock.Manual, function string, native map[string]lambdaTargetsMetric) {
	t.Helper()
	advanceClock(t, source, time.Minute)
	if _, err := c.cloud.RunDueJobs(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	client := metricsClient(cloudClients{c.server}, "test")
	for name, expected := range native {
		out, err := client.GetMetricStatistics(t.Context(), &cloudwatch.GetMetricStatisticsInput{
			Namespace: aws.String("AWS/Lambda"), MetricName: &name,
			Dimensions: []metrictypes.Dimension{{Name: aws.String("FunctionName"), Value: &function}},
			StartTime:  aws.Time(time.Date(2026, 9, 14, 14, 59, 0, 0, time.UTC)), EndTime: aws.Time(source.Now().Add(time.Minute)),
			Period: aws.Int32(60), Statistics: []metrictypes.Statistic{metrictypes.StatisticSum, metrictypes.StatisticSampleCount},
		})
		if err != nil {
			t.Fatal(err)
		}
		var sum, count float64
		for _, point := range out.Datapoints {
			sum += aws.ToFloat64(point.Sum)
			count += aws.ToFloat64(point.SampleCount)
		}
		if sum != aws.ToFloat64(expected.Sum) || count != aws.ToFloat64(expected.SampleCount) {
			t.Fatalf("%s %s sum/count=%v/%v, native=%v/%v", function, name, sum, count, aws.ToFloat64(expected.Sum), aws.ToFloat64(expected.SampleCount))
		}
		if (name == "DestinationDeliveryFailures" || name == "DeadLetterErrors") && aws.ToFloat64(expected.Sum) == 0 && len(out.Datapoints) != 0 {
			t.Fatalf("%s %s emitted absent native failure samples: %+v", function, name, out.Datapoints)
		}
	}
}

func TestLambdaDockerNativeEventBridgeAndLambdaDestinations(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture := lambdaTargetsFixture[struct {
				Captures struct {
					Delivery lambdaTargetsCapture `json:"delivery"`
				} `json:"captures"`
				Metrics struct {
					Rounds []struct {
						Aggregates map[string]map[string]lambdaTargetsMetric `json:"aggregates"`
					} `json:"rounds"`
				} `json:"retained_metrics"`
			}](t, "outcomes_events")
			f := fixture.Captures.Delivery
			c, source := lambdaTargetsCloud(t, backend)
			queue, err := c.queues.CreateQueue(t.Context(), lambdaEventsInput[sqs.CreateQueueInput](t, f.lambdaEventsFixture, "create_queue"))
			if err != nil {
				t.Fatal(err)
			}
			c.outputURL = queue.QueueUrl
			if _, err := c.events.CreateEventBus(t.Context(), lambdaEventsInput[eventbridge.CreateEventBusInput](t, f.lambdaEventsFixture, "create_bus")); err != nil {
				t.Fatal(err)
			}
			if _, err := c.events.PutRule(t.Context(), lambdaEventsInput[eventbridge.PutRuleInput](t, f.lambdaEventsFixture, "create_rule")); err != nil {
				t.Fatal(err)
			}
			policy := lambdaEventsInput[sqs.SetQueueAttributesInput](t, f.lambdaEventsFixture, "queue_resource_policy")
			policy.QueueUrl = queue.QueueUrl
			if _, err := c.queues.SetQueueAttributes(t.Context(), policy); err != nil {
				t.Fatal(err)
			}
			targets, err := c.events.PutTargets(t.Context(), lambdaEventsInput[eventbridge.PutTargetsInput](t, f.lambdaEventsFixture, "target_queue"))
			if err != nil || targets.FailedEntryCount != 0 {
				t.Fatalf("EventBridge consumer target: %+v %v", targets, err)
			}
			root := (cloudClients{c.server}).iam("test", "test", "")
			for _, kind := range []string{"eventbridge", "lambda", "collector"} {
				if _, err := root.CreateRole(t.Context(), lambdaEventsInput[iam.CreateRoleInput](t, f.lambdaEventsFixture, "create_role_"+kind)); err != nil {
					t.Fatal(err)
				}
				lambdaTargetsPolicy(t, c, f.lambdaEventsFixture, "initial_policy_"+kind)
			}
			collectorARN := lambdaTargetsCreate(t, c, f.lambdaEventsFixture, "create_stackd-leo-57d463777b-collector_1", queue.QueueUrl)
			lambdaTargetsConfig(t, c, source, f.lambdaEventsFixture, "collector_retry_one")
			lambdaTargetsCreate(t, c, f.lambdaEventsFixture, "create_stackd-leo-57d463777b-eb_0", queue.QueueUrl)
			lambdaTargetsCreate(t, c, f.lambdaEventsFixture, "create_stackd-leo-57d463777b-lf_0", queue.QueueUrl)
			for _, kind := range []string{"eventbridge", "lambda"} {
				lambdaTargetsPolicy(t, c, f.lambdaEventsFixture, "working_policy_"+kind)
				lambdaTargetsConfig(t, c, source, f.lambdaEventsFixture, "valid_destination_"+kind)
			}
			for _, invocation := range f.Invocations {
				label := invocation.Label
				t.Run(label, func(t *testing.T) {
					kind := "lambda"
					if strings.HasPrefix(label, "eventbridge_") {
						kind = "eventbridge"
					}
					if strings.HasSuffix(label, "_revoked") {
						lambdaTargetsPolicy(t, c, f.lambdaEventsFixture, "revoked_policy_"+kind)
					}
					if strings.HasSuffix(label, "_repaired") {
						lambdaTargetsPolicy(t, c, f.lambdaEventsFixture, "repaired_policy_"+kind)
					}
					completed := source.Now()
					id := lambdaTargetsInvoke(t, c, f.lambdaEventsFixture, label, invocation.Payload)
					count := 2
					if strings.HasSuffix(label, "_revoked") {
						count = 1
					}
					messages := lambdaEventsReceive(t, c, queue.QueueUrl, count)
					var witness, destination map[string]any
					for _, message := range messages {
						body := lambdaTargetsJSON(t, []byte(aws.ToString(message.Body)))
						if body["kind"] == "source_execution" {
							witness = body
						} else {
							destination = body
						}
					}
					if witness == nil || witness["runtime_request_id"] != id || !reflect.DeepEqual(witness["event"], lambdaTargetsJSON(t, invocation.Payload)) {
						t.Fatalf("original source runtime did not witness accepted event: %#v", witness)
					}
					if count == 1 {
						// The handler's own authority probe corroborates revocation;
						// destination denial must not retry a successful source.
						probe, ok := witness["authority_probe"].(map[string]any)
						if !ok || probe["Error"] == nil {
							t.Fatalf("missing runtime denial witness: %#v", witness)
						}
						lambdaTargetsIdle(t, c)
						lambdaEventsQuiet(t, c, queue.QueueUrl)
						return
					}
					var native map[string]any
					for _, receipt := range f.Deliveries {
						if receipt.Label == label && receipt.Body["kind"] != "source_execution" {
							native = receipt.Body
							break
						}
					}
					if native == nil || destination == nil {
						t.Fatalf("missing native or local destination for %s", label)
					}
					if kind == "eventbridge" {
						record := destination["detail"].(map[string]any)
						lambdaTargetsRecord(t, record, native["detail"].(map[string]any), id, completed)
						for _, key := range []string{"version", "detail-type", "source", "account", "region", "resources"} {
							if !reflect.DeepEqual(destination[key], native[key]) {
								t.Fatalf("EventBridge %s: got %#v, native %#v", key, destination[key], native[key])
							}
						}
						if destination["id"] == nil || destination["id"] == "" || destination["time"] != completed.UTC().Format(time.RFC3339) {
							// RFC3339 without fractional seconds is the native bus envelope.
							t.Fatalf("EventBridge identity/second-resolution time: %#v", destination)
						}
					} else {
						lambdaTargetsRecord(t, destination["input"].(map[string]any), native["input"].(map[string]any), id, completed)
						collectorID := destination["collector_runtime_request_id"]
						if collectorID == nil || collectorID == "" || collectorID == id || destination["collector_invoked_function_arn"] != collectorARN {
							t.Fatalf("destination Lambda did not actually execute independently: %#v", destination)
						}
						if label == "lambda_collector_failure" {
							lambdaEventsAwaitRetry(t, c, source.Now().Add(time.Minute))
							advanceClock(t, source, time.Minute)
							retry := lambdaTargetsJSON(t, []byte(aws.ToString(lambdaEventsReceive(t, c, queue.QueueUrl, 1)[0].Body)))
							if retry["collector_runtime_request_id"] != collectorID || retry["collector_invoked_function_arn"] != collectorARN || !reflect.DeepEqual(retry["input"], destination["input"]) {
								t.Fatalf("collector retry changed its accepted event/request identity: first %#v, retry %#v", destination, retry)
							}
						}
					}
					lambdaTargetsIdle(t, c)
					lambdaEventsQuiet(t, c, queue.QueueUrl)
				})
			}
			for function, metrics := range fixture.Metrics.Rounds[len(fixture.Metrics.Rounds)-1].Aggregates {
				lambdaTargetsMetrics(t, c, source, function, metrics)
			}
		})
	}
}

func TestLambdaDockerNativeS3FailureDestinations(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture := lambdaTargetsFixture[struct {
				lambdaEventsFixture
				Invocations []struct {
					Label   string `json:"label"`
					Payload []byte `json:"payload_base64"`
				} `json:"invocations"`
				Deliveries []struct {
					Label  string         `json:"source_label"`
					Record map[string]any `json:"record"`
					Get    struct {
						Output struct {
							ContentType          string
							Metadata             map[string]string
							ServerSideEncryption string
						} `json:"output"`
					} `json:"get_object_result"`
				} `json:"actual_deliveries"`
				Metrics []struct {
					Values map[string]lambdaTargetsMetric `json:"values"`
				} `json:"metric_snapshots"`
			}](t, "outcomes_s3")
			f := fixture.lambdaEventsFixture
			c, source := lambdaTargetsCloud(t, backend)
			clients := cloudClients{c.server}
			buckets, logs, root := s3NativeClient(clients, "test", "test"), logsClient(clients, "test"), clients.iam("test", "test", "")
			createBucket := lambdaEventsInput[s3.CreateBucketInput](t, f, "create_private_bucket")
			bucket := createBucket.Bucket
			if _, err := buckets.CreateBucket(t.Context(), createBucket); err != nil {
				t.Fatal(err)
			}
			if _, err := root.CreateRole(t.Context(), lambdaEventsInput[iam.CreateRoleInput](t, f, "create_role")); err != nil {
				t.Fatal(err)
			}
			if _, err := logs.CreateLogGroup(t.Context(), lambdaEventsInput[cloudwatchlogs.CreateLogGroupInput](t, f, "create_owned_log_group")); err != nil {
				t.Fatal(err)
			}
			lambdaTargetsPolicy(t, c, f, "role_policy_none")
			functionARN := lambdaTargetsCreate(t, c, f, "create_function_0", nil)
			function := aws.ToString(lambdaEventsInput[awslambda.CreateFunctionInput](t, f, "create_function_0").FunctionName)
			for _, probe := range []struct{ policy, config string }{
				{"role_policy_none", "no_s3_permissions_admission"},
				{"role_policy_put_only", "put_only_admission"},
				{"role_policy_list_only", "list_only_admission"},
			} {
				lambdaTargetsPolicy(t, c, f, probe.policy)
				_, err := c.lambda.PutFunctionEventInvokeConfig(t.Context(), lambdaEventsInput[awslambda.PutFunctionEventInvokeConfigInput](t, f, probe.config))
				assertAPIError(t, err, "InvalidParameterValueException")
			}
			lambdaTargetsPolicy(t, c, f, "role_policy_both")
			lambdaTargetsConfig(t, c, source, f, "both_permissions_positive_config")
			seen := map[string]bool{}
			for _, invocation := range fixture.Invocations {
				t.Run(invocation.Label, func(t *testing.T) {
					switch invocation.Label {
					case "deny_list_existing_config":
						lambdaTargetsPolicy(t, c, f, "role_policy_deny_list")
						_, err := c.lambda.PutFunctionEventInvokeConfig(t.Context(), lambdaEventsInput[awslambda.PutFunctionEventInvokeConfigInput](t, f, "explicit_deny_list_config_rejection"))
						assertAPIError(t, err, "InvalidParameterValueException")
					case "deny_put_existing_config":
						lambdaTargetsPolicy(t, c, f, "role_policy_deny_put")
						_, err := c.lambda.PutFunctionEventInvokeConfig(t.Context(), lambdaEventsInput[awslambda.PutFunctionEventInvokeConfigInput](t, f, "explicit_deny_put_config_probe"))
						assertAPIError(t, err, "InvalidParameterValueException")
					case "repaired_positive_control":
						lambdaTargetsPolicy(t, c, f, "role_policy_both")
						lambdaTargetsConfig(t, c, source, f, "repair_config")
					case "after_clear_failure":
						if _, err := c.lambda.UpdateFunctionEventInvokeConfig(t.Context(), lambdaEventsInput[awslambda.UpdateFunctionEventInvokeConfigInput](t, f, "clear_on_failure_destination")); err != nil {
							t.Fatal(err)
						}
						advanceClock(t, source, 2*time.Minute)
						if _, err := c.cloud.RunDueJobs(t.Context(), 100); err != nil {
							t.Fatal(err)
						}
					case "restored_after_clear_positive":
						lambdaTargetsConfig(t, c, source, f, "restore_after_clear")
					}
					if len(invocation.Payload) == 0 {
						t.Fatalf("native fixture lacks original payload bytes for %s", invocation.Label)
					}
					completed := source.Now()
					id := lambdaTargetsInvoke(t, c, f, invocation.Label+"_invoke", invocation.Payload)
					lambdaTargetsIdle(t, c)
					// Even denied/cleared deliveries must prove one real execution
					// of the original failing handler, rather than mere admission.
					var receipts []map[string]any
					deadline := time.Now().Add(time.Minute)
					for {
						receipts = alarmDeliveryLogs(t, logs, "/aws/lambda/"+function, "STACKD_RECEIPT ")
						var found []map[string]any
						for _, receipt := range receipts {
							if receipt["case"] == invocation.Label {
								found = append(found, receipt)
							}
						}
						if len(found) != 0 {
							if len(found) != 1 || found[0]["aws_request_id"] != id || found[0]["invoked_function_arn"] != functionARN || found[0]["function_version"] != "$LATEST" {
								t.Fatalf("original S3 source runtime receipt: %#v", found)
							}
							break
						}
						if time.Now().After(deadline) {
							t.Fatalf("no real runtime receipt for %s: %#v", invocation.Label, receipts)
						}
						if _, err := c.cloud.RunDueJobs(t.Context(), 100); err != nil {
							t.Fatal(err)
						}
						time.Sleep(20 * time.Millisecond)
					}
					listed, err := buckets.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: bucket})
					if err != nil {
						t.Fatal(err)
					}
					wantDelivery := invocation.Label != "deny_put_existing_config" && invocation.Label != "after_clear_failure"
					wantCount := len(seen)
					if wantDelivery {
						wantCount++
					}
					if len(listed.Contents) != wantCount {
						t.Fatalf("%s object count=%d, want %d", invocation.Label, len(listed.Contents), wantCount)
					}
					for _, object := range listed.Contents {
						key := aws.ToString(object.Key)
						if seen[key] {
							continue
						}
						seen[key] = true
						prefix := "aws/lambda/async/" + function + "/" + completed.UTC().Format("2006/01/02/2006-01-02T15.04.05-")
						if !strings.HasPrefix(key, prefix) || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(strings.TrimPrefix(key, prefix)) {
							t.Fatalf("S3 destination key is not native extensionless timestamp/UUID: %q", key)
						}
						out, err := buckets.GetObject(t.Context(), &s3.GetObjectInput{Bucket: bucket, Key: object.Key})
						if err != nil {
							t.Fatal(err)
						}
						body, err := io.ReadAll(out.Body)
						out.Body.Close()
						if err != nil {
							t.Fatal(err)
						}
						matched := false
						for _, native := range fixture.Deliveries {
							if native.Label != invocation.Label {
								continue
							}
							matched = true
							lambdaTargetsRecord(t, lambdaTargetsJSON(t, body), native.Record, id, completed)
							if aws.ToString(out.ContentType) != native.Get.Output.ContentType || string(out.ServerSideEncryption) != native.Get.Output.ServerSideEncryption || !maps.Equal(out.Metadata, native.Get.Output.Metadata) {
								t.Fatalf("native S3 content type/encryption/metadata: %+v", out)
							}
						}
						if !matched {
							t.Fatalf("unexpected S3 object for %s", invocation.Label)
						}
					}
				})
			}
			lambdaTargetsMetrics(t, c, source, function, fixture.Metrics[len(fixture.Metrics)-1].Values)
		})
	}
}
