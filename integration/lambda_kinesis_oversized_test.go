package stackd_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"stackd/clock"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type lambdaKinesisOversizedFixture struct {
	lambdaKinesisFixture
	Blobs map[string]struct {
		Encoding  string
		Data      string
		UTF8Bytes int    `json:"utf8_bytes"`
		SHA256    string `json:"sha256"`
	}
}

// Native zero/nonzero retry quotas distinguish terminal admission failures
// from unconditional discard or an age-only stall. A successful source invoke
// is the warm barrier; native bootstrap repetitions are not delivery rules.
func TestLambdaKinesisDockerNativeOversized(t *testing.T) {
	lambdaURLDocker(t)
	for _, fixture := range []string{"kinesis_oversized", "kinesis_oversized_retries"} {
		t.Run(fixture, func(t *testing.T) {
			testLambdaKinesisNativeOversized(t, fixture)
		})
	}
}

func testLambdaKinesisNativeOversized(t *testing.T, fixtureName string) {
	capture := lambdaFixture[lambdaKinesisOversizedFixture](t, fixtureName)
	blobs := map[string]string{}
	for name, blob := range capture.Blobs {
		if blob.Encoding != "gzip+base64" {
			t.Fatalf("unsupported native blob encoding %s", blob.Encoding)
		}
		compressed, err := base64.StdEncoding.DecodeString(blob.Data)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		closeErr := reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		if len(data) != blob.UTF8Bytes || fmt.Sprintf("%x", sha256.Sum256(data)) != blob.SHA256 {
			t.Fatalf("native blob %s failed lossless evidence validation", name)
		}
		blobs[name] = string(data)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, label := range []string{"consumer_oversized", "standard_oversized"} {
			t.Run(backend+"/"+label, func(t *testing.T) {
				fixture := capture.lambdaKinesisFixture
				var warmExpected, nextExpected *lambdaDynamoDBInvocation
				for _, invocation := range fixture.Delivery[label+"_after_large"].Invocations {
					records := invocation.Event["Records"].([]any)
					if len(records) != 1 {
						t.Fatalf("native oversized workflow changed batch shape: %+v", invocation)
					}
					ordinal := lambdaKinesisRecordData(t, records[0].(map[string]any))["ordinal"]
					if ordinal == float64(0) && warmExpected == nil {
						warmExpected = &invocation
					}
					if ordinal == float64(2) {
						nextExpected = &invocation
					}
				}
				if warmExpected == nil || nextExpected == nil {
					t.Fatalf("native %s has no successful warm/successor evidence", label)
				}
				source := clock.NewManual(fixture.StartedAt)
				clients, _ := lambdaKinesisCloud(t, backend, source)
				replace, _ := lambdaKinesisNativeSetup(t, fixture, clients, source)
				call := func(row lambdaURLRow) any { return lambdaKinesisCall(t, clients, row, replace) }
				call(fixture.row(t, "set_max_record_size"))
				awaitKinesisActive(t, source, clients.kinesis("test", "test", ""), fixture.Prefix)
				queue := call(fixture.row(t, "create_destination")).(*sqs.CreateQueueOutput)
				call(fixture.row(t, "policy_owned-destination"))
				call(fixture.row(t, label+"_alias"))
				input := lambdaStreamingInput[awslambda.CreateEventSourceMappingInput](t, fixture.row(t, label+"_create").Input, replace)
				mapping, err := lambdaDynamoDBClient(clients).CreateEventSourceMapping(t.Context(), &input)
				if err != nil {
					t.Fatal(err)
				}
				id := aws.ToString(mapping.UUID)
				lambdaKinesisMappingState(t, clients, source, id, "Disabled")
				warm := call(fixture.row(t, label+"_put_0")).(*kinesis.PutRecordOutput)
				if _, err := lambdaDynamoDBClient(clients).UpdateEventSourceMapping(t.Context(), &awslambda.UpdateEventSourceMappingInput{UUID: &id, Enabled: aws.Bool(true)}); err != nil {
					t.Fatal(err)
				}
				lambdaKinesisInvocations(t, clients, source, fixture.Prefix, "KINESIS_PROBE ", 1)
				largeRow := fixture.row(t, label+"_put_1")
				largeInput := lambdaStreamingInput[map[string]any](t, largeRow.Input, strings.NewReplacer())
				largeRow.Input = lambdaQualifiedJSON(t, lambdaDynamoDBWindowExpand(t, largeInput, blobs))
				large := call(largeRow).(*kinesis.PutRecordOutput)
				nextRow := fixture.row(t, label+"_put_2")
				next := call(nextRow).(*kinesis.PutRecordOutput)
				got := lambdaKinesisInvocations(t, clients, source, fixture.Prefix, "KINESIS_PROBE ", 2)
				if len(got) != 2 {
					t.Fatalf("oversized record reached the runtime or replayed its neighbors: %+v", got)
				}
				warmRecord := warmExpected.Event["Records"].([]any)[0].(map[string]any)
				warmSequence := warmRecord["kinesis"].(map[string]any)["sequenceNumber"].(string)
				warmShard := strings.SplitN(warmRecord["eventID"].(string), ":", 2)[0]
				bind := strings.NewReplacer(warmSequence, aws.ToString(warm.SequenceNumber), warmShard, aws.ToString(warm.ShardId), largeRow.Result.Output["SequenceNumber"].(string), aws.ToString(large.SequenceNumber), nextRow.Result.Output["SequenceNumber"].(string), aws.ToString(next.SequenceNumber))
				for i, native := range []*lambdaDynamoDBInvocation{warmExpected, nextExpected} {
					expected := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, native.Event), replace)
					expected = lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, expected), bind)
					if !reflect.DeepEqual(lambdaKinesisComparableEvent(t, got[i].Event), lambdaKinesisComparableEvent(t, expected)) {
						t.Fatalf("oversized neighbor %d differs from native delivery: got %s want %s", i, lambdaQualifiedJSON(t, got[i].Event), lambdaQualifiedJSON(t, expected))
					}
				}
				// Native bootstrap warm markers can expire too. Select the large
				// record's destination by its accepted sequence, not the first body.
				selected := fixture
				selected.DestinationMessages = nil
				for _, message := range fixture.DestinationMessages {
					var body map[string]any
					if err := json.Unmarshal([]byte(message.Body), &body); err != nil {
						t.Fatal(err)
					}
					if body["KinesisBatchInfo"].(map[string]any)["startSequenceNumber"] == largeRow.Result.Output["SequenceNumber"] {
						selected.DestinationMessages = append(selected.DestinationMessages, message)
					}
				}
				if len(selected.DestinationMessages) != 1 {
					t.Fatalf("native large record has %d matching destinations", len(selected.DestinationMessages))
				}
				lambdaKinesisNativeDestination(t, clients, source, queue.QueueUrl, selected, label, replace, bind)
			})
		}
	}
}
