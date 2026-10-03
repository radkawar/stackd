package stackd_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awstest"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type lambdaKinesisFixture struct {
	lambdaURLFixture
	Delivery map[string]struct {
		Invocations []lambdaDynamoDBInvocation `json:"invocations"`
	} `json:"delivery"`
	DestinationMessages []struct {
		Body string
	} `json:"destination_messages"`
}

func lambdaKinesisCall(t *testing.T, clients cloudClients, row lambdaURLRow, replace *strings.Replacer) any {
	t.Helper()
	if row.Service != "kinesis" {
		return lambdaDynamoDBCall(t, clients, row, replace)
	}
	out, err := awstest.CallSDK(t.Context(), clients.kinesis("test", "test", ""), row.Operation, json.RawMessage(replace.Replace(string(row.Input))))
	if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	return out
}

// The captured Python ZIP runs in Lambda Docker and reads records from Kafka.
// Native envelopes and retry batches are compared, not reconstructed from the
// emulator. The extra mismatched JSON record proves the filter consumes data.
func TestLambdaKinesisDockerNativeDelivery(t *testing.T) {
	lambdaURLDocker(t)
	sourceFixture := lambdaFixture[lambdaKinesisFixture](t, "kinesis_source")
	for _, backend := range []string{"memory", "sqlite"} {
		for _, label := range []string{"partial_off", "partial_on", "consumer_partial", "timestamp", "kpl_standard", "kpl_consumer", "hash_consumer", "kpl_invalid_standard", "kpl_invalid_consumer", "consumer_destination", "standard_destination", "partial_bisect_destination"} {
			t.Run(backend+"/"+label, func(t *testing.T) {
				fixture := sourceFixture
				nativeLabel := label
				nativeDestination := label == "consumer_destination" || label == "standard_destination"
				if nativeDestination {
					fixture = lambdaFixture[lambdaKinesisFixture](t, "kinesis_destination")
				}
				if label == "kpl_standard" || label == "kpl_consumer" || label == "hash_consumer" {
					fixture = lambdaFixture[lambdaKinesisFixture](t, "kinesis_reshard")
				}
				if strings.HasPrefix(label, "kpl_invalid_") {
					fixture = lambdaFixture[lambdaKinesisFixture](t, "kinesis_followup")
				}
				if label == "partial_bisect_destination" {
					fixture = lambdaFixture[lambdaKinesisFixture](t, "kinesis_followup")
					nativeLabel = "partial_bisect"
				}
				want := fixture.Delivery[nativeLabel].Invocations
				if len(want) == 0 {
					t.Fatalf("native capture has no delivery evidence for %s", nativeLabel)
				}
				source := clock.NewManual(fixture.StartedAt)
				clients, reopen := lambdaKinesisCloud(t, backend, source)
				replace, streamARN := lambdaKinesisNativeSetup(t, fixture, clients, source)
				call := func(row lambdaURLRow) any { return lambdaKinesisCall(t, clients, row, replace) }
				var queueURL *string
				if nativeDestination {
					queueURL = call(fixture.row(t, "create_destination")).(*sqs.CreateQueueOutput).QueueUrl
					call(fixture.row(t, "policy_owned-destination"))
				}
				call(fixture.row(t, nativeLabel+"_alias"))
				if label == "hash_consumer" {
					client := clients.kinesis("test", "test", "")
					shards, err := client.ListShards(t.Context(), &kinesis.ListShardsInput{StreamARN: &streamARN})
					if err != nil {
						t.Fatal(err)
					}
					if _, err := client.SplitShard(t.Context(), &kinesis.SplitShardInput{StreamARN: &streamARN, ShardToSplit: shards.Shards[0].ShardId, NewStartingHashKey: aws.String("170141183460469231731687303715884105728")}); err != nil {
						t.Fatal(err)
					}
					awaitKinesisActive(t, source, client, fixture.Prefix)
				}
				var identities []string
				for _, row := range fixture.Observations {
					if row.Operation != "put-record" || !strings.HasPrefix(row.Label, nativeLabel+"_put_") {
						continue
					}
					if delay := row.StartedAt.Sub(source.Now()); delay > 0 {
						advanceClock(t, source, delay)
					}
					if strings.HasSuffix(row.Label, "_1") {
						if _, err := clients.kinesis("test", "test", "").PutRecord(t.Context(), &kinesis.PutRecordInput{StreamARN: &streamARN, PartitionKey: aws.String("filtered-key"), Data: []byte(`{"phase":"not-this-mapping","ordinal":99}`)}); err != nil {
							t.Fatal(err)
						}
					}
					out := call(row).(*kinesis.PutRecordOutput)
					identities = append(identities, row.Result.Output["SequenceNumber"].(string), aws.ToString(out.SequenceNumber), row.Result.Output["ShardId"].(string), aws.ToString(out.ShardId))
				}
				input := lambdaStreamingInput[map[string]any](t, fixture.row(t, nativeLabel+"_create").Input, replace)
				if seconds, ok := input["StartingPositionTimestamp"].(float64); ok {
					input["StartingPositionTimestamp"] = time.Unix(0, int64(seconds*float64(time.Second))).UTC().Format(time.RFC3339Nano)
				}
				mappingInput := lambdaStreamingInput[awslambda.CreateEventSourceMappingInput](t, lambdaQualifiedJSON(t, input), strings.NewReplacer())
				if label == "partial_bisect_destination" {
					queue, err := clients.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("kinesis-failures")})
					if err != nil {
						t.Fatal(err)
					}
					queueURL = queue.QueueUrl
					queueARN := "arn:aws:sqs:us-east-1:000000000000:kinesis-failures"
					var roleInput struct{ RoleName string }
					if err := json.Unmarshal(fixture.row(t, "create_role").Input, &roleInput); err != nil {
						t.Fatal(err)
					}
					putRolePolicy(t, clients.iam("test", "test", ""), roleInput.RoleName, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"`+queueARN+`"}}`)
					mappingInput.BisectBatchOnFunctionError = aws.Bool(true)
					mappingInput.DestinationConfig = &lambdatypes.DestinationConfig{OnFailure: &lambdatypes.OnFailure{Destination: &queueARN}}
				}
				mapping, err := lambdaDynamoDBClient(clients).CreateEventSourceMapping(t.Context(), &mappingInput)
				if err != nil {
					t.Fatal(err)
				}
				id := aws.ToString(mapping.UUID)
				lambdaKinesisMappingState(t, clients, source, id, "Disabled")
				clients = reopen()
				lambdaKinesisMappingState(t, clients, source, id, "Disabled")
				if _, err := lambdaDynamoDBClient(clients).UpdateEventSourceMapping(t.Context(), &awslambda.UpdateEventSourceMappingInput{UUID: &id, Enabled: aws.Bool(true)}); err != nil {
					t.Fatal(err)
				}
				got := lambdaKinesisInvocations(t, clients, source, fixture.Prefix, "KINESIS_PROBE ", len(want))
				if len(got) != len(want) {
					t.Fatalf("invocations=%d native=%d: %+v", len(got), len(want), got)
				}
				// Preserve opaque identities by binding each accepted native write
				// to its SDK counterpart. KPL subsequence identity remains compared.
				bind := strings.NewReplacer(identities...)
				for i := range want {
					identities = append(identities, want[i].RequestID, got[i].RequestID)
					expected := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, want[i].Event), replace)
					expected = lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, expected), bind)
					actual := lambdaKinesisComparableEvent(t, got[i].Event)
					expected = lambdaKinesisComparableEvent(t, expected)
					if !reflect.DeepEqual(actual, expected) || got[i].InvokedARN != replace.Replace(want[i].InvokedARN) {
						t.Fatalf("invocation %d payload\ngot %s\nwant %s", i, lambdaQualifiedJSON(t, actual), lambdaQualifiedJSON(t, expected))
					}
					for j := range i {
						if (got[i].RequestID == got[j].RequestID) != (want[i].RequestID == want[j].RequestID) {
							t.Fatalf("retained retry request identity changed for invocations %d,%d", j, i)
						}
					}
				}
				if nativeDestination {
					lambdaKinesisNativeDestination(t, clients, source, queueURL, fixture, nativeLabel, replace, strings.NewReplacer(identities...))
				} else if queueURL != nil {
					lambdaKinesisFailureDestination(t, clients, source, queueURL, streamARN, got)
				}
			})
		}
	}
}

func lambdaKinesisComparableEvent(t *testing.T, event map[string]any) map[string]any {
	t.Helper()
	cloned := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, event), strings.NewReplacer())
	for _, item := range cloned["Records"].([]any) {
		record := item.(map[string]any)
		data := record["kinesis"].(map[string]any)
		if timestamp, ok := data["approximateArrivalTimestamp"].(float64); !ok || timestamp <= 0 {
			t.Fatalf("Kinesis event lacks numeric arrival timestamp: %+v", record)
		}
		delete(data, "approximateArrivalTimestamp")
	}
	return cloned
}

// This is an SDK contract check, not a claimed native destination capture.
func lambdaKinesisFailureDestination(t *testing.T, clients cloudClients, source *clock.Manual, queueURL *string, streamARN string, invocations []lambdaDynamoDBInvocation) {
	t.Helper()
	var failed map[string]any
	attempts := 0
	for _, invocation := range invocations {
		records := invocation.Event["Records"].([]any)
		if len(records) == 1 && lambdaKinesisRecordData(t, records[0].(map[string]any))["bad"] == true {
			failed = records[0].(map[string]any)
			attempts++
		}
	}
	if failed == nil {
		t.Fatal("bisection never isolated the failed record")
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		advanceClock(t, source, 250*time.Millisecond)
		out, err := clients.sqs("test", "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queueURL, MaxNumberOfMessages: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Messages) == 0 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if len(out.Messages) != 1 {
			t.Fatalf("discarded batch produced %d destination messages", len(out.Messages))
		}
		var body struct {
			RequestContext struct {
				Condition              string
				ApproximateInvokeCount int
			}
			KinesisBatchInfo struct {
				StreamArn, ShardId, StartSequenceNumber, EndSequenceNumber string
				BatchSize                                                  int
			}
		}
		if err := json.Unmarshal([]byte(aws.ToString(out.Messages[0].Body)), &body); err != nil {
			t.Fatal(err)
		}
		sequence := failed["kinesis"].(map[string]any)["sequenceNumber"].(string)
		shard := strings.SplitN(failed["eventID"].(string), ":", 2)[0]
		if body.RequestContext.Condition != "RetryAttemptsExhausted" || body.RequestContext.ApproximateInvokeCount != attempts || body.KinesisBatchInfo.StreamArn != streamARN || body.KinesisBatchInfo.ShardId != shard || body.KinesisBatchInfo.StartSequenceNumber != sequence || body.KinesisBatchInfo.EndSequenceNumber != sequence || body.KinesisBatchInfo.BatchSize != 1 {
			t.Fatalf("discarded singleton destination lost invocation context: %s", aws.ToString(out.Messages[0].Body))
		}
		return
	}
	t.Fatal("discarded Kinesis batch did not reach SQS")
}

func lambdaKinesisNativeDestination(t *testing.T, clients cloudClients, source *clock.Manual, queueURL *string, fixture lambdaKinesisFixture, label string, replace, bind *strings.Replacer) {
	t.Helper()
	var expected map[string]any
	for _, message := range fixture.DestinationMessages {
		document := lambdaStreamingInput[map[string]any](t, []byte(message.Body), replace)
		if strings.HasSuffix(document["requestContext"].(map[string]any)["functionArn"].(string), ":"+label) {
			expected = lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, document), bind)
			break
		}
	}
	if expected == nil {
		t.Fatalf("native capture has no %s destination evidence", label)
	}
	deadline := time.Now().Add(90 * time.Second)
	var actual map[string]any
	for time.Now().Before(deadline) {
		advanceClock(t, source, 250*time.Millisecond)
		out, err := clients.sqs("test", "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queueURL, MaxNumberOfMessages: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Messages) != 0 {
			if len(out.Messages) != 1 {
				t.Fatalf("single captured discard produced %d destination messages", len(out.Messages))
			}
			if err := json.Unmarshal([]byte(aws.ToString(out.Messages[0].Body)), &actual); err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if actual == nil {
		t.Fatal("native discarded Kinesis batch did not reach SQS")
	}
	_, invoked := expected["responseContext"]
	for _, document := range []map[string]any{actual, expected} {
		if !invoked {
			// Rejected before runtime admission: no handler request ID exists to
			// bind. The destination still has its own nonempty request identity.
			context := document["requestContext"].(map[string]any)
			if id, ok := context["requestId"].(string); !ok || id == "" {
				t.Fatalf("discarded uninvoked batch has no request identity: %+v", document)
			}
			delete(context, "requestId")
		}
		if _, err := time.Parse(time.RFC3339Nano, document["timestamp"].(string)); err != nil {
			t.Fatal(err)
		}
		delete(document, "timestamp")
		info := document["KinesisBatchInfo"].(map[string]any)
		for _, field := range []string{"approximateArrivalOfFirstRecord", "approximateArrivalOfLastRecord"} {
			if _, err := time.Parse(time.RFC3339Nano, info[field].(string)); err != nil {
				t.Fatal(err)
			}
			delete(info, field)
		}
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Kinesis destination\ngot %s\nwant %s", lambdaQualifiedJSON(t, actual), lambdaQualifiedJSON(t, expected))
	}
}
