package stackd_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"maps"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd"
	"stackd/clock"
)

// This replay selects requests from retained native evidence, not generated
// approximations of its large boundary records. AWS buffering, retries, ordering,
// compression bytes and object packing are not timing or partition guarantees.
// The manual clock and reopen operations exercise our local persistence policy.
func TestFirehoseNativeS3Delivery(t *testing.T) {
	var plan struct {
		Source, MetricSource string
		Setup                []string
		Plain, Gzip          struct {
			Create, MetricPrefix string
			Puts                 []string
			HeadSequence         int
		}
		Buffered   struct{ Lengthen, Before, Update, After, Shorten string }
		Boundaries []string
		Denied     struct{ Policy, Put, Describe, Logs, Restore, After string }
	}
	awsReadFixture(t, "firehose/"+"delivery_replay.json", &plan)
	var native, metricNative firehoseNativeFixture
	awsReadFixture(t, "firehose/"+plan.Source, &native)
	awsReadFixture(t, "firehose/"+plan.MetricSource, &metricNative)
	var plain, compressed firehose.CreateDeliveryStreamInput
	if err := json.Unmarshal(native.row(t, plan.Plain.Create).Input, &plain); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(native.row(t, plan.Gzip.Create).Input, &compressed); err != nil {
		t.Fatal(err)
	}
	bucket := strings.TrimPrefix(aws.ToString(plain.ExtendedS3DestinationConfiguration.BucketARN), "arn:aws:s3:::")
	plainName, gzipName := aws.ToString(plain.DeliveryStreamName), aws.ToString(compressed.DeliveryStreamName)
	plainPrefix := aws.ToString(plain.ExtendedS3DestinationConfiguration.Prefix)
	gzipPrefix := aws.ToString(compressed.ExtendedS3DestinationConfiguration.Prefix)

	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			start := native.StartedAt.UTC().Truncate(time.Minute)
			source := clock.NewManual(start)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: native.Account, Clock: source})
			var plainRecords, gzipRecords [][]byte
			// The real IAM policy, S3 bucket and configured Logs destinations all
			// come from the same native setup as the delivery requests.
			replay := func(label string) any {
				row := native.row(t, label)
				var client any
				switch row.Service {
				case "s3":
					client = s3NativeClient(clients, "test", "test")
				case "iam":
					client = clients.iam("test", "test", "")
				case "logs":
					client = logsClient(clients, "test")
				case "firehose":
					client = clients.firehose("test", "test", "")
				default:
					t.Fatalf("unsupported replay service %q", row.Service)
				}
				out := firehoseReplayCall(t, client, row, func(input any) {
					if update, ok := input.(*firehose.UpdateDestinationInput); ok {
						description, err := clients.firehose("test", "test", "").DescribeDeliveryStream(t.Context(), &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: update.DeliveryStreamName})
						if err != nil {
							t.Fatal(err)
						}
						update.CurrentDeliveryStreamVersionId = description.DeliveryStreamDescription.VersionId
						update.DestinationId = description.DeliveryStreamDescription.Destinations[0].DestinationId
					}
				})
				if row.Result.Code == "Success" && (row.Operation == "PutRecord" || row.Operation == "PutRecordBatch") {
					var input struct {
						DeliveryStreamName string
						Record             firehosetypes.Record
						Records            []firehosetypes.Record
					}
					if err := json.Unmarshal(row.Input, &input); err != nil {
						t.Fatal(err)
					}
					if row.Operation == "PutRecord" {
						input.Records = []firehosetypes.Record{input.Record}
					}
					if batch, ok := out.(*firehose.PutRecordBatchOutput); ok {
						if aws.ToInt32(batch.FailedPutCount) != 0 || len(batch.RequestResponses) != len(input.Records) {
							t.Fatalf("%s: accepted batch lost records: %+v", label, batch)
						}
						for _, result := range batch.RequestResponses {
							if result.ErrorCode != nil {
								t.Fatalf("%s: record rejected: %+v", label, result)
							}
						}
					}
					for _, record := range input.Records {
						if input.DeliveryStreamName == plainName {
							plainRecords = append(plainRecords, record.Data)
						} else if input.DeliveryStreamName == gzipName {
							gzipRecords = append(gzipRecords, record.Data)
						} else {
							t.Fatalf("unexpected stream %q", input.DeliveryStreamName)
						}
					}
				}
				return out
			}
			for _, label := range plan.Setup {
				replay(label)
			}
			awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), plainName)
			awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), gzipName)
			for _, label := range plan.Plain.Puts {
				replay(label)
			}
			for _, label := range plan.Gzip.Puts {
				replay(label)
			}
			clients = reopen()
			plainObjects := firehoseAwaitDelivery(t, clients, source, bucket, plainPrefix, plainRecords, false, native, plan.Plain.HeadSequence)
			gzipObjects := firehoseAwaitDelivery(t, clients, source, bucket, gzipPrefix, gzipRecords, true, native, plan.Gzip.HeadSequence)

			replay(plan.Buffered.Lengthen)
			awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), plainName)
			initialCount := len(plainRecords)
			replay(plan.Buffered.Before)
			if got := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), bucket, plainPrefix); !reflect.DeepEqual(got, plainObjects) {
				t.Fatal("buffered record delivered before prefix update")
			}
			replay(plan.Buffered.Update)
			awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), plainName)
			replay(plan.Buffered.After)
			var update firehose.UpdateDestinationInput
			if err := json.Unmarshal(native.row(t, plan.Buffered.Update).Input, &update); err != nil {
				t.Fatal(err)
			}
			updatedPrefix := aws.ToString(update.ExtendedS3DestinationUpdate.Prefix)
			clients = reopen() // accepted bytes and the current prefix must both survive.
			firehoseAwaitDelivery(t, clients, source, bucket, updatedPrefix, plainRecords[initialCount:], false, native, plan.Plain.HeadSequence)
			if got := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), bucket, plainPrefix); !reflect.DeepEqual(got, plainObjects) {
				t.Fatal("prefix update sent retained records to obsolete prefix")
			}

			replay(plan.Buffered.Shorten)
			awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), plainName)
			for _, label := range plan.Boundaries {
				replay(label)
			}
			updatedObjects := firehoseAwaitDelivery(t, clients, source, bucket, updatedPrefix, plainRecords[initialCount:], false, native, plan.Plain.HeadSequence)
			// A clean minute isolates failed-attempt zeros from earlier successful
			// objects. The number or cadence of retries is intentionally unpinned.
			advanceClock(t, source, source.Now().Truncate(time.Minute).Add(time.Minute).Sub(source.Now()))
			failureStart := source.Now()
			replay(plan.Denied.Policy)
			replay(plan.Denied.Put)
			advanceClock(t, source, 2*time.Minute)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			active := replay(plan.Denied.Describe).(*firehose.DescribeDeliveryStreamOutput).DeliveryStreamDescription
			if active.DeliveryStreamStatus != "ACTIVE" {
				t.Fatalf("destination denial changed stream status to %s", active.DeliveryStreamStatus)
			}
			if got := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), bucket, updatedPrefix); !reflect.DeepEqual(got, updatedObjects) {
				t.Fatal("denied destination wrote accepted records")
			}
			firehoseDeliveryDiagnostic(t, clients, native.row(t, plan.Denied.Logs), aws.ToString(active.VersionId))
			// Attempts run at the advanced instant; publish their completed
			// minute before querying CloudWatch's exclusive EndTime boundary.
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			for _, metric := range []string{"DeliveryToS3.Bytes", "DeliveryToS3.Records", "DeliveryToS3.Success"} {
				got := firehoseDeliveryStatistics(t, clients, metricNative.row(t, plan.Plain.MetricPrefix+"-"+metric), failureStart, source.Now())
				if got.Count == 0 || got.Sum != 0 || got.Min != 0 || got.Max != 0 {
					t.Fatalf("%s denied attempts: %+v; want observed zero-valued samples", metric, got)
				}
			}
			clients = reopen() // retain the failed prepared object, not merely fresh puts.
			replay(plan.Denied.Restore)
			replay(plan.Denied.After)
			updatedObjects = firehoseAwaitDelivery(t, clients, source, bucket, updatedPrefix, plainRecords[initialCount:], false, native, plan.Plain.HeadSequence)
			advanceClock(t, source, 2*time.Minute)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			for _, stream := range []struct {
				Prefix  string
				Records [][]byte
				Objects int
			}{
				{plan.Plain.MetricPrefix, plainRecords, len(plainObjects) + len(updatedObjects)},
				{plan.Gzip.MetricPrefix, gzipRecords, len(gzipObjects)},
			} {
				for _, metric := range []string{"IncomingBytes", "IncomingRecords"} {
					row := metricNative.row(t, stream.Prefix+"-"+metric)
					got := firehoseDeliveryStatistics(t, clients, row, start, source.Now())
					var expected cloudwatch.GetMetricStatisticsOutput
					if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
						t.Fatal(err)
					}
					want := firehoseCollapseStatistics(expected)
					if got != want {
						t.Fatalf("%s %s: %+v; native aggregate %+v", stream.Prefix, metric, got, want)
					}
				}
				bytes := 0
				for _, record := range stream.Records {
					bytes += len(record)
				}
				success := firehoseDeliveryStatistics(t, clients, metricNative.row(t, stream.Prefix+"-DeliveryToS3.Success"), start, source.Now())
				if success.Sum != float64(stream.Objects) || success.Max != 1 {
					t.Fatalf("%s delivery success does not count actual objects: %+v", stream.Prefix, success)
				}
				if stream.Prefix == plan.Plain.MetricPrefix && (success.Min != 0 || success.Count <= success.Sum) {
					t.Fatalf("failed delivery attempts missing from success distribution: %+v", success)
				}
				for metric, sum := range map[string]float64{"DeliveryToS3.Bytes": float64(bytes), "DeliveryToS3.Records": float64(len(stream.Records)), "DeliveryToS3.Success": float64(stream.Objects)} {
					got := firehoseDeliveryStatistics(t, clients, metricNative.row(t, stream.Prefix+"-"+metric), start, source.Now())
					if got.Sum != sum || got.Count != success.Count {
						t.Fatalf("%s %s: %+v; want sum %g and %g object-attempt samples", stream.Prefix, metric, got, sum, success.Count)
					}
					if stream.Prefix == plan.Gzip.MetricPrefix && got.Count != float64(stream.Objects) {
						t.Fatalf("successful delivery metric sampled records instead of objects: %+v", got)
					}
				}
			}
		})
	}
}

// Match complete input records against each object, consuming each exactly once.
// This permits any object partition and record order but no corruption, duplication,
// rejected-record leakage, lost bytes, or final processor delimiter. Empty records
// have no observable byte boundary; their contribution is checked through metrics.
func firehoseAwaitDelivery(t *testing.T, clients cloudClients, source *clock.Manual, bucket, prefix string, records [][]byte, compressed bool, native firehoseNativeFixture, headSequence int) map[string][]byte {
	t.Helper()
	var objects map[string][]byte
	wantBytes, nonempty := 0, 0
	for _, record := range records {
		wantBytes += len(record)
		if len(record) != 0 {
			nonempty++
		}
	}
	for range 90 {
		trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
		objects = firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), bucket, prefix)
		decoded := make(map[string][]byte, len(objects))
		gotBytes := 0
		for key, body := range objects {
			if compressed {
				reader, err := gzip.NewReader(bytes.NewReader(body))
				if err != nil {
					t.Fatalf("%s is not gzip: %v", key, err)
				}
				body, err = io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
			}
			decoded[key] = body
			gotBytes += len(body)
		}
		expected := wantBytes
		if compressed {
			expected += nonempty - len(objects)
		}
		if len(objects) != 0 && gotBytes >= expected {
			if gotBytes != expected {
				t.Fatalf("%s delivered %d decoded bytes; expected %d", prefix, gotBytes, expected)
			}
			used := make([]bool, len(records))
			for key, body := range decoded {
				for len(body) != 0 {
					match := -1
					for i, record := range records {
						if !used[i] && len(record) != 0 && bytes.HasPrefix(body, record) && (match < 0 || len(record) > len(records[match])) {
							match = i
						}
					}
					if match < 0 {
						t.Fatalf("%s contains unexpected, duplicated or corrupted bytes at remaining length %d", key, len(body))
					}
					used[match] = true
					body = body[len(records[match]):]
					if compressed && len(body) != 0 {
						if body[0] != '\n' || len(body) == 1 {
							t.Fatalf("%s lacks an inter-record delimiter or has a final delimiter", key)
						}
						body = body[1:]
					}
				}
			}
			for i, record := range records {
				if len(record) != 0 && !used[i] {
					t.Fatalf("%s missing record %d (%d bytes)", prefix, i, len(record))
				}
			}
			firehoseDeliveryMetadata(t, s3NativeClient(clients, "test", "test"), bucket, objects, native, headSequence, compressed)
			return objects
		}
		advanceClock(t, source, 10*time.Second)
	}
	t.Fatalf("%s did not deliver retained records within the local replay bound (%d objects)", prefix, len(objects))
	return nil
}

func firehoseDeliveryMetadata(t *testing.T, client *s3.Client, bucket string, objects map[string][]byte, native firehoseNativeFixture, sequence int, compressed bool) {
	t.Helper()
	var expected s3.HeadObjectOutput
	found := false
	for _, row := range native.Calls {
		if row.Sequence == sequence {
			if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
				t.Fatal(err)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing native HeadObject sequence %d", sequence)
	}
	for key := range objects {
		got, err := client.HeadObject(t.Context(), &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
		if err != nil {
			t.Fatal(err)
		}
		if aws.ToString(got.ContentType) != aws.ToString(expected.ContentType) || aws.ToString(got.ContentEncoding) != aws.ToString(expected.ContentEncoding) || got.ServerSideEncryption != expected.ServerSideEncryption || !maps.Equal(got.Metadata, expected.Metadata) {
			t.Fatalf("%s metadata: type=%q encoding=%q encryption=%q custom=%v; native type=%q encoding=%q encryption=%q custom=%v", key, aws.ToString(got.ContentType), aws.ToString(got.ContentEncoding), got.ServerSideEncryption, got.Metadata, aws.ToString(expected.ContentType), aws.ToString(expected.ContentEncoding), expected.ServerSideEncryption, expected.Metadata)
		}
		if compressed && !strings.HasSuffix(key, ".gz") {
			t.Fatalf("gzip object lacks native extension: %s", key)
		}
	}
}

func firehoseDeliveryDiagnostic(t *testing.T, clients cloudClients, row firehoseNativeCall, version string) {
	t.Helper()
	var input cloudwatchlogs.FilterLogEventsInput
	var native struct {
		Events []struct{ LogStreamName, Message string }
	}
	if err := json.Unmarshal(row.Input, &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(row.Result.Output, &native); err != nil {
		t.Fatal(err)
	}
	if len(native.Events) == 0 {
		t.Fatal("native denied destination has no diagnostic")
	}
	var expected map[string]any
	if err := json.Unmarshal([]byte(native.Events[0].Message), &expected); err != nil {
		t.Fatal(err)
	}
	expected["deliveryStreamVersionId"] = version
	// The native diagnostic's wording, event ID, timestamps, and retry count are
	// not asserted; routing, error category and affected stream/destination are.
	input.StartTime = nil
	for {
		out, err := logsClient(clients, "test").FilterLogEvents(t.Context(), &input)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range out.Events {
			var actual map[string]any
			if err := json.Unmarshal([]byte(aws.ToString(event.Message)), &actual); err != nil {
				t.Fatal(err)
			}
			if aws.ToString(event.LogStreamName) != native.Events[0].LogStreamName {
				continue
			}
			match := true
			for _, field := range []string{"deliveryStreamARN", "destination", "deliveryStreamVersionId", "errorCode"} {
				if actual[field] != expected[field] {
					match = false
				}
			}
			if match {
				return
			}
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == aws.ToString(input.NextToken) {
			break
		}
		input.NextToken = out.NextToken
	}
	t.Fatal("configured Logs destination did not receive the native S3.AccessDenied diagnostic")
}

type firehoseStatisticTotals struct{ Count, Sum, Min, Max float64 }

func firehoseCollapseStatistics(out cloudwatch.GetMetricStatisticsOutput) firehoseStatisticTotals {
	result := firehoseStatisticTotals{Min: math.Inf(1), Max: math.Inf(-1)}
	for _, point := range out.Datapoints {
		result.Count += aws.ToFloat64(point.SampleCount)
		result.Sum += aws.ToFloat64(point.Sum)
		result.Min = math.Min(result.Min, aws.ToFloat64(point.Minimum))
		result.Max = math.Max(result.Max, aws.ToFloat64(point.Maximum))
	}
	return result
}

func firehoseDeliveryStatistics(t *testing.T, clients cloudClients, row firehoseNativeCall, start, end time.Time) firehoseStatisticTotals {
	t.Helper()
	out := firehoseReplayCall(t, metricsClient(clients, "test"), row, func(value any) {
		input := value.(*cloudwatch.GetMetricStatisticsInput)
		input.StartTime, input.EndTime = &start, &end
	}).(*cloudwatch.GetMetricStatisticsOutput)
	return firehoseCollapseStatistics(*out)
}
