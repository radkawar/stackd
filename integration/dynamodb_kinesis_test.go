package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"

	"stackd"
	"stackd/clock"
	dynamoengine "stackd/engine/dynamodb"
	"stackd/internal/awstest"
)

// Replays selected calls and complete envelopes from the owned native capture,
// rather than manufacturing expectations from the destination implementation.
func TestDynamoDBKinesisNativeDestination(t *testing.T) {
	var fixture struct {
		Source, Account string
		Start           time.Time
		Steps           []struct {
			Name, Advance  string
			Calls, Records []int
			Extra          []dynamoNativeRow
			Await          int
			Reopen, Check  bool
		}
	}
	raw, err := os.ReadFile("../testdata/dynamodb/kinesis_replay.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var native struct {
		Account   string
		Resources map[string]string
		Calls     []dynamoNativeRow
		Records   []struct{ Decoded json.RawMessage }
	}
	dynamoReadJSON(t, fixture.Source, &native)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			logs := newKinesisReplayRuntime(t)
			runtime, err := dynamoengine.NewDocker(t.Context(), dynamoengine.DockerConfig{Client: logs.client})
			if err != nil {
				t.Fatal(err)
			}
			owned := &dynamoReplayRuntime{Runtime: runtime}
			// Services close before native removal; failed Open attempts are owned too.
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				for _, spec := range owned.specifications() {
					if err := runtime.Remove(ctx, spec); err != nil {
						t.Errorf("remove native database %s: %v", spec.ID, err)
					}
				}
			})
			source := clock.NewManual(fixture.Start)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source, DynamoDBRuntime: owned, KinesisRuntime: logs})
			name := "ddb-kinesis-" + backend
			streamARN := "arn:aws:kinesis:us-east-1:" + fixture.Account + ":stream/" + name
			bindings := map[string]string{native.Account: fixture.Account, native.Resources["tableName"]: name, "$table": name}
			bound := func(raw json.RawMessage) json.RawMessage { return json.RawMessage(aasReplace(string(raw), bindings)) }
			ddb := func() *dynamodb.Client { return dynamoClient(clients, "test", "test", clients.server.Client()) }
			kin := func() *kinesis.Client { return clients.kinesis("test", "test", "") }
			drain := func(t *testing.T) {
				t.Helper()
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				result, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000)
				if err != nil || result.More {
					t.Fatalf("destination jobs did not drain: %+v %v", result, err)
				}
			}
			call := func(t *testing.T, row dynamoNativeRow) {
				t.Helper()
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				input := bound(row.Input)
				var out any
				var err error
				switch row.Service {
				case "kinesis":
					out, err = awstest.CallSDK(ctx, kin(), row.Operation, input)
				case "iam":
					out, err = awstest.CallSDK(ctx, clients.iam("test", "test", ""), row.Operation, input)
				default:
					out, err = awstest.CallSDK(ctx, ddb(), row.Operation, json.RawMessage(`{}`), func(target any) { dynamoSDKInput(t, target, input) })
				}
				if row.Code != "" && row.Code != "Success" {
					assertAPIError(t, err, row.Code)
					return
				}
				if err != nil {
					t.Fatalf("native row %d %s: %v", row.Sequence, row.Operation, err)
				}
				switch out := out.(type) {
				case *kinesis.CreateStreamOutput:
					awaitKinesisActive(t, source, kin(), name)
				case *dynamodb.CreateTableOutput:
					if err := dynamoWaitActive(t.Context(), ddb(), name); err != nil {
						t.Fatal(err)
					}
				case *dynamodb.EnableKinesisStreamingDestinationOutput:
					if string(out.DestinationStatus) != "ENABLING" {
						t.Fatalf("enable: %+v", out)
					}
				case *dynamodb.UpdateKinesisStreamingDestinationOutput:
					if string(out.DestinationStatus) != "UPDATING" {
						t.Fatalf("update: %+v", out)
					}
				case *dynamodb.DisableKinesisStreamingDestinationOutput:
					if string(out.DestinationStatus) != "DISABLING" {
						t.Fatalf("disable: %+v", out)
					}
				case *dynamodb.DescribeKinesisStreamingDestinationOutput:
					if len(out.KinesisDataStreamDestinations) != 0 {
						t.Fatalf("fresh table has destinations: %+v", out)
					}
				case *iam.GetRoleOutput:
					want := ecsControlBody(t, bound(row.Output))["Role"].(map[string]any)
					if out.Role == nil || aws.ToString(out.Role.Arn) != want["Arn"] || aws.ToString(out.Role.Path) != want["Path"] {
						t.Fatalf("service-linked role differs: %+v", out.Role)
					}
				case *iam.ListAttachedRolePoliciesOutput:
					want := ecsControlBody(t, row.Output)["AttachedPolicies"].([]any)
					if len(out.AttachedPolicies) != 1 || aws.ToString(out.AttachedPolicies[0].PolicyArn) != want[0].(map[string]any)["PolicyArn"] {
						t.Fatalf("service-linked role lacks native policy: %+v", out.AttachedPolicies)
					}
				}
			}
			var expected []json.RawMessage
			markers := 0
			for _, step := range fixture.Steps {
				if !t.Run(step.Name, func(t *testing.T) {
					for _, number := range step.Calls {
						row := native.Calls[number-1]
						if row.Sequence != number {
							t.Fatalf("native call %d moved", number)
						}
						call(t, row)
					}
					if step.Advance != "" {
						duration, err := time.ParseDuration(step.Advance)
						if err != nil {
							t.Fatal(err)
						}
						advanceClock(t, source, duration)
						drain(t)
					}
					if step.Reopen {
						clients = reopen()
					}
					if step.Await != 0 {
						want := ecsControlBody(t, bound(native.Calls[step.Await-1].Output))["KinesisDataStreamDestinations"].([]any)[0].(map[string]any)
						awaitDynamoKinesisDestination(t, source, ddb(), name, want)
					}
					for _, extra := range step.Extra {
						call(t, extra)
					}
					for _, number := range step.Records {
						expected = append(expected, bound(native.Records[number-1].Decoded))
					}
					if !step.Check {
						return
					}
					drain(t)
					// A real final Kafka record fences each finite observation window.
					// No sleep or empty poll is taken as proof that delivery completed.
					markers++
					marker := fmt.Sprintf("stackd-ddb-kinesis-barrier-%d", markers)
					if _, err := kin().PutRecord(t.Context(), &kinesis.PutRecordInput{StreamARN: &streamARN, PartitionKey: aws.String("replay-barrier"), Data: []byte(marker)}); err != nil {
						t.Fatal(err)
					}
					records := awaitKinesisRecords(t, source, kin(), streamARN, len(expected)+markers)
					var data [][]byte
					seenMarkers := map[string]bool{}
					partitions := map[string]string{}
					for _, record := range records {
						if strings.HasPrefix(string(record.Data), "stackd-ddb-kinesis-barrier-") {
							seenMarkers[string(record.Data)] = true
							continue
						}
						value := ecsControlBody(t, record.Data)
						key := dynamoKinesisRecordKey(value)
						partition := aws.ToString(record.PartitionKey)
						if partition == "" || (partitions[key] != "" && partitions[key] != partition) {
							t.Fatalf("partition affinity changed for %s", key)
						}
						partitions[key] = partition
						data = append(data, record.Data)
					}
					if len(records) != len(expected)+markers || len(seenMarkers) != markers || !seenMarkers[marker] {
						t.Fatalf("observation did not reach exact barrier: records=%d markers=%v", len(records), seenMarkers)
					}
					compareDynamoKinesisRecords(t, data, expected, fixture.Start, source.Now())
				}) {
					return
				}
			}
			// Destination capture must not silently turn on public DynamoDB Streams.
			table, err := ddb().DescribeTable(t.Context(), &dynamodb.DescribeTableInput{TableName: &name})
			if err != nil {
				t.Fatal(err)
			}
			if table.Table.StreamSpecification != nil || table.Table.LatestStreamArn != nil {
				t.Fatalf("destination enabled public streams: %+v", table.Table)
			}
			item, err := ddb().GetItem(t.Context(), &dynamodb.GetItemInput{TableName: &name, Key: map[string]dynamodbtypes.AttributeValue{"pk": &dynamodbtypes.AttributeValueMemberS{Value: "after-drain"}}, ConsistentRead: aws.Bool(true)})
			if err != nil || len(item.Item) != 1 {
				t.Fatalf("terminal write did not reach native table: %+v %v", item, err)
			}
		})
	}
}

func awaitDynamoKinesisDestination(t *testing.T, source *clock.Manual, client *dynamodb.Client, table string, want map[string]any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		advanceClock(t, source, 100*time.Millisecond)
		out, err := client.DescribeKinesisStreamingDestination(ctx, &dynamodb.DescribeKinesisStreamingDestinationInput{TableName: &table})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.KinesisDataStreamDestinations) == 1 {
			d := out.KinesisDataStreamDestinations[0]
			if d.DestinationStatus == dynamodbtypes.DestinationStatusEnableFailed && want["DestinationStatus"] != "ENABLE_FAILED" {
				t.Fatalf("destination activation failed: %s", aws.ToString(d.DestinationStatusDescription))
			}
			precision, _ := want["ApproximateCreationDateTimePrecision"].(string)
			if string(d.DestinationStatus) == want["DestinationStatus"] && aws.ToString(d.StreamArn) == want["StreamArn"] && string(d.ApproximateCreationDateTimePrecision) == precision {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("destination did not reach native state %+v: %v", want, ctx.Err())
}

func dynamoKinesisRecordKey(value map[string]any) string {
	return value["dynamodb"].(map[string]any)["Keys"].(map[string]any)["pk"].(map[string]any)["S"].(string)
}

func compareDynamoKinesisRecords(t *testing.T, actual [][]byte, expected []json.RawMessage, start, end time.Time) {
	t.Helper()
	got, want := map[string][]any{}, map[string][]any{}
	ids := map[string]bool{}
	for _, raw := range actual {
		value := ecsControlBody(t, raw)
		id, _ := value["eventID"].(string)
		if id == "" || ids[id] {
			t.Fatalf("missing or duplicate destination event ID: %q", id)
		}
		ids[id] = true
		detail := value["dynamodb"].(map[string]any)
		timestamp, ok := detail["ApproximateCreationDateTime"].(float64)
		lower, upper := start.UnixMilli(), end.UnixMilli()
		if detail["ApproximateCreationDateTimePrecision"] == "MICROSECOND" {
			lower, upper = start.UnixMicro(), end.UnixMicro()
		}
		if !ok || timestamp != float64(int64(timestamp)) || timestamp < float64(lower) || timestamp > float64(upper) {
			t.Fatalf("wrong event timestamp units/value: %+v", detail)
		}
		delete(value, "eventID")
		delete(detail, "ApproximateCreationDateTime")
		dynamoUnordered(value)
		key := dynamoKinesisRecordKey(value)
		got[key] = append(got[key], value)
	}
	for _, raw := range expected {
		value := ecsControlBody(t, raw)
		delete(value, "eventID")
		delete(value["dynamodb"].(map[string]any), "ApproximateCreationDateTime")
		dynamoUnordered(value)
		key := dynamoKinesisRecordKey(value)
		want[key] = append(want[key], value)
	}
	// Replication arrival ordering is not an AWS guarantee; retain multiplicity
	// and full old/new images instead of pinning one capture's scheduling order.
	for key := range got {
		dynamoSort(got[key])
	}
	for key := range want {
		dynamoSort(want[key])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("destination envelopes differ\ngot: %#v\nwant: %#v", got, want)
	}
}
