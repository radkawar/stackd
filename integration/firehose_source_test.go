package stackd_test

import (
	"bytes"
	"encoding/json"
	"maps"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd"
	"stackd/clock"
)

// This selection replays retained commands, not a second hand-authored source
// scenario. Reopens extend the observed read-denial recovery with local durability.
func TestFirehoseKinesisSourceNativeReplaySDK(t *testing.T) {
	var plan struct {
		Source                             string
		Setup                              []string
		BeforeCreate, Create, BeforeActive string
		Steps                              []struct {
			Name                 string
			Calls, Objects       []string
			Diagnostic, Status   string
			Reopen, SourceAbsent bool
		}
	}
	awsReadFixture(t, "firehose/"+"source_replay.json", &plan)
	var native firehoseNativeFixture
	awsReadFixture(t, "firehose/"+plan.Source, &native)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			runtime := newKinesisReplayRuntime(t)
			source := clock.NewManual(native.StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: native.Account, Clock: source, KinesisRuntime: runtime})
			var create firehose.CreateDeliveryStreamInput
			if err := json.Unmarshal(native.row(t, plan.Create).Input, &create); err != nil {
				t.Fatal(err)
			}
			name := aws.ToString(create.DeliveryStreamName)
			var bucket s3.CreateBucketInput
			if err := json.Unmarshal(native.row(t, "create-bucket").Input, &bucket); err != nil {
				t.Fatal(err)
			}
			var stream kinesis.CreateStreamInput
			if err := json.Unmarshal(native.row(t, "create-source").Input, &stream); err != nil {
				t.Fatal(err)
			}
			call := func(label string) any {
				t.Helper()
				row := native.row(t, label)
				var client any
				switch row.Service {
				case "firehose":
					client = clients.firehose("test", "test", "")
				case "kinesis":
					client = clients.kinesis("test", "test", "")
				case "s3":
					client = s3NativeClient(clients, "test", "test")
				case "logs":
					client = logsClient(clients, "test")
				case "iam":
					client = clients.iam("test", "test", "")
				default:
					t.Fatalf("unhandled source fixture service %q", row.Service)
				}
				return firehoseReplayCall(t, client, row)
			}
			for _, label := range plan.Setup {
				call(label)
				if native.row(t, label).Operation == "CreateStream" {
					awaitKinesisActive(t, source, clients.kinesis("test", "test", ""), aws.ToString(stream.StreamName))
				}
			}
			call(plan.BeforeCreate)
			// Native writes straddled Create; do not turn this into an unresolved
			// concurrent timestamp tie by freezing both operations at one instant.
			advanceClock(t, source, time.Second)
			call(plan.Create)
			call(plan.BeforeActive)
			awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), name)
			for _, step := range plan.Steps {
				t.Log(step.Name)
				for _, label := range step.Calls {
					call(label)
				}
				if step.SourceAbsent {
					advanceClock(t, source, time.Second)
					waiter := kinesis.NewStreamNotExistsWaiter(clients.kinesis("test", "test", ""), func(options *kinesis.StreamNotExistsWaiterOptions) {
						options.MinDelay, options.MaxDelay = 50*time.Millisecond, 100*time.Millisecond
					})
					if err := waiter.Wait(t.Context(), &kinesis.DescribeStreamInput{StreamName: stream.StreamName}, time.Minute); err != nil {
						t.Fatal(err)
					}
					firehoseReplayCall(t, clients.kinesis("test", "test", ""), native.row(t, "source-disappearance-absence-2"))
				}
				if step.Diagnostic != "" {
					firehoseAwaitSourceDiagnostic(t, source, logsClient(clients, "test"), native.row(t, step.Diagnostic))
				}
				wanted := map[string]int{}
				for _, label := range step.Objects {
					var object struct{ Body []byte }
					if err := json.Unmarshal(native.row(t, label).Result.Output, &object); err != nil {
						t.Fatal(err)
					}
					for line, count := range firehoseSourceLines(t, object.Body) {
						wanted[line] += count
					}
				}
				var got map[string]int
				for range 100 {
					got = map[string]int{}
					for _, body := range firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), aws.ToString(bucket.Bucket), aws.ToString(create.ExtendedS3DestinationConfiguration.Prefix)) {
						for line, count := range firehoseSourceLines(t, body) {
							got[line] += count
						}
					}
					if maps.Equal(got, wanted) {
						break
					}
					advanceClock(t, source, 5*time.Second)
				}
				if !maps.Equal(got, wanted) {
					t.Fatalf("S3 consumer bytes differ from retained native markers: got %v, want %v", got, wanted)
				}
				actual := call(step.Status).(*firehose.DescribeDeliveryStreamOutput)
				var expected struct {
					DeliveryStreamDescription struct{ DeliveryStreamStatus string }
				}
				if err := json.Unmarshal(native.row(t, step.Status).Result.Output, &expected); err != nil {
					t.Fatal(err)
				}
				if string(actual.DeliveryStreamDescription.DeliveryStreamStatus) != expected.DeliveryStreamDescription.DeliveryStreamStatus {
					t.Fatalf("source failure changed Firehose lifecycle: %s", actual.DeliveryStreamDescription.DeliveryStreamStatus)
				}
				if step.Reopen {
					clients = reopen()
				}
			}
		})
	}
}

func firehoseSourceLines(t *testing.T, body []byte) map[string]int {
	t.Helper()
	lines := map[string]int{}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		t.Fatalf("source record bytes lost their newline: %q", body)
	}
	for _, line := range bytes.Split(body[:len(body)-1], []byte{'\n'}) {
		lines[string(line)]++
	}
	return lines
}

func firehoseAwaitSourceDiagnostic(t *testing.T, source *clock.Manual, client *cloudwatchlogs.Client, row firehoseNativeCall) {
	t.Helper()
	var input cloudwatchlogs.GetLogEventsInput
	var expected struct{ Events []struct{ Message string } }
	if err := json.Unmarshal(row.Input, &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected.Events) == 0 {
		t.Fatal("native diagnostic selection contains no events")
	}
	type diagnostic struct {
		ErrorCode, DeliveryStreamARN, Destination string
		DeliveryStreamVersionID                   int
	}
	var wanted diagnostic
	if err := json.Unmarshal([]byte(expected.Events[len(expected.Events)-1].Message), &wanted); err != nil {
		t.Fatal(err)
	}
	if wanted.ErrorCode == "" {
		t.Fatal("native diagnostic contains no errorCode")
	}
	for range 100 {
		out, err := client.GetLogEvents(t.Context(), &input)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range out.Events {
			var got diagnostic
			if err := json.Unmarshal([]byte(aws.ToString(event.Message)), &got); err != nil {
				t.Fatal(err)
			}
			if got == wanted {
				return
			}
		}
		advanceClock(t, source, 5*time.Second)
	}
	t.Fatalf("configured source logs did not publish native diagnostic %+v", wanted)
}
