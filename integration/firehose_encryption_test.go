package stackd_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd"
	"stackd/clock"
)

// Destination encryption is independent of Firehose's ingestion encryption.
// Native evidence includes backup interval zero rejection in the first run and
// actual distinct-key primary/backup consumers in the later successful run.
func TestFirehoseS3KMSNativeDeliveryRecovery(t *testing.T) {
	var fixture struct {
		Setup, Calls, Objects []s3KMSCall
		Rejection             s3KMSCall
	}
	awsReadFixture(t, "firehose/encryption_replay.json.gz", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 19, 20, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source})
			replay := newS3KMSReplay(clients)
			for _, row := range fixture.Setup {
				replay.call(t, row)
			}
			replay.call(t, fixture.Rejection)
			replay.call(t, fixture.Calls[0])
			var create firehose.CreateDeliveryStreamInput
			if err := json.Unmarshal(replay.rebind(t, fixture.Calls[0].Input), &create); err != nil {
				t.Fatal(err)
			}
			awaitFirehoseActive(t, source, replay.clients.firehose("test", "test", ""), aws.ToString(create.DeliveryStreamName))
			replay.call(t, fixture.Calls[1])
			firehoseKMSAwait(t, replay, source, fixture.Objects[:2])
			replay.call(t, fixture.Calls[2]) // deny GenerateDataKey on primary key only
			replay.call(t, fixture.Calls[3]) // accepted into the retained stream
			trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
			advanceClock(t, source, 30*time.Second)
			trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
			// The native denied window retained only the first primary record;
			// no timing claim is made about the independent backup's flush.
			first := firehoseSourceLines(t, s3KMSDecode(t, *fixture.Objects[0].Plaintext))
			actual := map[string]int{}
			for _, body := range firehoseConsumerObjects(t, replay.s3Client("caller"), "s3-kms-replay-data", "firehose/primary/") {
				for line, count := range firehoseSourceLines(t, body) {
					actual[line] += count
				}
			}
			if !reflect.DeepEqual(actual, first) {
				t.Fatalf("primary delivered during KMS denial: %v want %v", actual, first)
			}
			// This reopen is local durability coverage, not an AWS restart claim.
			replay.clients = reopen()
			replay.call(t, fixture.Calls[4]) // restore the captured role policy
			firehoseKMSAwait(t, replay, source, fixture.Objects)
			replay.clients = reopen()
			firehoseKMSAwait(t, replay, source, fixture.Objects)
		})
	}
}

func firehoseKMSAwait(t *testing.T, replay *s3KMSReplay, source *clock.Manual, objects []s3KMSCall) {
	t.Helper()
	for range 120 {
		trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
		complete := true
		for _, prefix := range []string{"firehose/primary/", "firehose/backup/"} {
			want := map[string]int{}
			var expected map[string]any
			for _, row := range objects {
				var input s3.GetObjectInput
				if err := json.Unmarshal(replay.rebind(t, row.Input), &input); err != nil {
					t.Fatal(err)
				}
				if !strings.HasPrefix(aws.ToString(input.Key), prefix) {
					continue
				}
				for line, count := range firehoseSourceLines(t, s3KMSDecode(t, *row.Plaintext)) {
					want[line] += count
				}
				if err := json.Unmarshal(replay.rebind(t, row.Output), &expected); err != nil {
					t.Fatal(err)
				}
			}
			got := map[string]int{}
			for key, body := range firehoseConsumerObjects(t, replay.s3Client("caller"), "s3-kms-replay-data", prefix) {
				for line, count := range firehoseSourceLines(t, body) {
					got[line] += count
				}
				head, err := replay.s3Client("caller").HeadObject(t.Context(), &s3.HeadObjectInput{Bucket: aws.String("s3-kms-replay-data"), Key: &key})
				if err != nil {
					t.Fatal(err)
				}
				if string(head.ServerSideEncryption) != expected["ServerSideEncryption"] || aws.ToString(head.SSEKMSKeyId) != expected["SSEKMSKeyId"] || head.BucketKeyEnabled != nil {
					t.Fatalf("%s: destination encryption differs from native consumer: %+v", key, head)
				}
			}
			for line, count := range got {
				if count > want[line] {
					t.Fatalf("unexpected or duplicate encrypted delivery %q: %d want %d", line, count, want[line])
				}
			}
			if !reflect.DeepEqual(want, got) {
				complete = false
			}
		}
		if complete {
			return
		}
		advanceClock(t, source, 5*time.Second)
	}
	t.Fatal("encrypted primary/backup consumers did not receive the native plaintext records")
}
