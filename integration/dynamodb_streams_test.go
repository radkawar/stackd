package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	dynamoengine "stackd/engine/dynamodb"
	"stackd/internal/awstest"
)

type dynamoStreamsWorkflow struct {
	Name     string
	Segments []struct {
		dynamoReplaySegment
		Iterator int
		Records  []int
	}
}

func TestDynamoDBStreamsNativeReplay(t *testing.T) {
	if os.Getenv("STACKD_DYNAMODB_DOCKER") != "1" {
		t.Skip("set STACKD_DYNAMODB_DOCKER=1 to exercise pinned DynamoDB Local")
	}
	var manifest struct{ Workflows []dynamoStreamsWorkflow }
	dynamoReadJSON(t, "streams_replay", &manifest)
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	runtime, err := dynamoengine.NewDocker(t.Context(), dynamoengine.DockerConfig{Client: engine})
	if err != nil {
		t.Fatal(err)
	}
	for _, workflow := range manifest.Workflows {
		t.Run(workflow.Name, func(t *testing.T) {
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					dynamoStreamsReplay(t, runtime, backend, workflow)
				})
			}
		})
	}
}

func dynamoStreamsReplay(t *testing.T, runtime dynamoengine.Runtime, backend string, workflow dynamoStreamsWorkflow) {
	t.Helper()
	source := clock.NewManual(time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC))
	observed := &dynamoReplayRuntime{Runtime: runtime}
	// Registered before retainedCloud: native resources outlive all service and
	// repository handles, including handles reconstructed by a reopen.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		for _, spec := range observed.specifications() {
			if err := runtime.Remove(ctx, spec); err != nil {
				t.Errorf("remove owned native database %s: %v", spec.ID, err)
			}
		}
	})
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "000000000000", Clock: source, DynamoDBRuntime: observed})
	_, key, secret := clients.user(t, "test", "Delegated")
	putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"*"`, "*"))
	bindings := map[string]string{}
	recordIDs := map[string]string{}
	sequences := map[string]map[string]string{}
	shards := map[string][]any{}
	tables := map[string]bool{}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		client := dynamoClient(clients, "test", "test", clients.server.Client())
		for table := range tables {
			if err := dynamoWaitActive(ctx, client, table); err != nil {
				t.Errorf("await native table %s: %v", table, err)
			}
			_, err := client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(table)})
			var absent *types.ResourceNotFoundException
			if err != nil && !errors.As(err, &absent) {
				t.Errorf("delete native table %s: %v", table, err)
			}
			if err := dynamoWaitAbsent(ctx, client, table); err != nil {
				t.Errorf("await native table deletion %s: %v", table, err)
			}
		}
	}()
	for _, segment := range workflow.Segments {
		var fixture struct{ Calls []dynamoNativeRow }
		dynamoReadJSON(t, segment.Source, &fixture)
		rowAt := func(number int) dynamoNativeRow {
			t.Helper()
			if number < 1 || number > len(fixture.Calls) {
				t.Fatalf("%s has no call %d", segment.Source, number)
			}
			row := fixture.Calls[number-1]
			if row.Sequence != 0 && row.Sequence != number {
				t.Fatalf("%s call %d moved to %d", segment.Source, number, row.Sequence)
			}
			return row
		}
		wire := &awstest.WireClient{Client: clients.server.Client()}
		ddb := dynamoClient(clients, key, secret, wire)
		streams := dynamodbstreams.New(dynamodbstreams.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: wire, RetryMaxAttempts: 1})
		call := func(t *testing.T, row dynamoNativeRow, input json.RawMessage) map[string]any {
			t.Helper()
			var client any = streams
			if row.Service == "dynamodb" {
				client = ddb
			} else if row.Service != "dynamodbstreams" {
				t.Fatalf("unselected prerequisite service %s", row.Service)
			}
			_, err := awstest.CallSDK(t.Context(), client, row.Operation, json.RawMessage(`{}`), func(target any) { dynamoSDKInput(t, target, input) })
			if row.Code == "Success" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				assertAPIError(t, err, row.Code)
			}
			status := row.HTTPStatus
			if status == 0 {
				status = 200
				if row.Code != "Success" {
					status = 400
				}
			}
			if wire.Status != status {
				t.Fatalf("HTTP status %d want %d", wire.Status, status)
			}
			return ecsControlBody(t, wire.Body)
		}
		for _, number := range segment.Rows {
			row := rowAt(number)
			if !t.Run(fmt.Sprintf("%s_%03d_%s", segment.Source, number, row.Label), func(t *testing.T) {
				if err := source.Advance(time.Second); err != nil {
					t.Fatal(err)
				}
				input := json.RawMessage(aasReplace(string(row.Input), bindings))
				actual := call(t, row, input)
				if row.Operation == "create-table" && row.Code == "Success" {
					tables[ecsControlBody(t, input)["TableName"].(string)] = true
				}
				expectedRaw := row.Output
				if len(row.Error) != 0 {
					expectedRaw = row.Error
				}
				expected := ecsControlBody(t, expectedRaw)
				backendTable := segment.Source == "engine" && (expected["Table"] != nil || expected["TableDescription"] != nil)
				for _, field := range []string{"TableDescription", "Table"} {
					if native, ok := expected[field].(map[string]any); ok {
						got := actual[field].(map[string]any)
						for _, identity := range []string{"TableArn", "LatestStreamArn", "LatestStreamLabel"} {
							dynamoStreamsBind(t, bindings, native, got, identity)
						}
						if spec, ok := native["StreamSpecification"]; ok && !backendTable {
							dynamoCompare(t, "stream-specification", map[string]any{"spec": spec}, map[string]any{"spec": got["StreamSpecification"]}, bindings, false)
						}
					}
				}
				switch row.Operation {
				case "list-streams":
					dynamoSort(expected["Streams"].([]any))
					dynamoSort(actual["Streams"].([]any))
				case "describe-stream":
					want := expected["StreamDescription"].(map[string]any)
					got := actual["StreamDescription"].(map[string]any)
					shards[got["StreamArn"].(string)] = got["Shards"].([]any)
					if segment.Source == "engine" {
						// Local's captured single shard must retain its identity on reopen.
						wantShards, gotShards := want["Shards"].([]any), got["Shards"].([]any)
						if len(wantShards) != len(gotShards) {
							t.Fatalf("shard count %d want %d", len(gotShards), len(wantShards))
						}
						for i := range wantShards {
							dynamoStreamsBind(t, bindings, wantShards[i].(map[string]any), gotShards[i].(map[string]any), "ShardId")
						}
					}
					for _, body := range []map[string]any{want, got} {
						delete(body, "Shards") // AWS partition topology is not a portable contract.
						delete(body, "CreationRequestDateTime")
					}
				case "delete-table":
					// Delete descriptions are asynchronous; the fixture's subsequent
					// absent-table and retained-stream reads are the stable contract.
					if err := dynamoWaitAbsent(t.Context(), ddb, ecsControlBody(t, input)["TableName"].(string)); err != nil {
						t.Fatal(err)
					}
					delete(tables, ecsControlBody(t, input)["TableName"].(string))
					return
				}
				// The engine capture owns native item/record behavior and recovery,
				// not AWS table responses (for example TableId and disable shape).
				// Those responses are compared against the live-AWS audit capture.
				if !backendTable {
					dynamoCompare(t, row.Operation, expected, actual, bindings, false)
				}
				if row.Code == "Success" && (row.Operation == "create-table" || row.Operation == "update-table") {
					table := ecsControlBody(t, input)["TableName"].(string)
					if err := dynamoWaitActive(t.Context(), ddb, table); err != nil {
						t.Fatal(err)
					}
				}
			}) {
				return
			}
		}
		if len(segment.Records) != 0 {
			iteratorRow := rowAt(segment.Iterator)
			input := ecsControlBody(t, []byte(aasReplace(string(iteratorRow.Input), bindings)))
			arn := input["StreamArn"].(string)
			var expected, actual []any
			for _, number := range segment.Records {
				expected = append(expected, ecsControlBody(t, rowAt(number).Output)["Records"].([]any)...)
			}
			for _, shard := range shards[arn] {
				input["ShardId"] = shard.(map[string]any)["ShardId"]
				raw, _ := json.Marshal(input)
				iterator := call(t, iteratorRow, raw)["ShardIterator"]
				recordRow := rowAt(segment.Records[0])
				recordInput := ecsControlBody(t, recordRow.Input)
				recordInput["ShardIterator"] = iterator
				raw, _ = json.Marshal(recordInput)
				records := call(t, recordRow, raw)["Records"].([]any)
				var prior *big.Int
				for _, record := range records {
					sequence := record.(map[string]any)["dynamodb"].(map[string]any)["SequenceNumber"].(string)
					number, ok := new(big.Int).SetString(sequence, 10)
					if !ok || (prior != nil && number.Cmp(prior) <= 0) {
						t.Fatalf("non-increasing shard sequence %q after %v", sequence, prior)
					}
					prior = number
				}
				actual = append(actual, records...)
			}
			if sequences[arn] == nil {
				sequences[arn] = map[string]string{}
			}
			dynamoStreamsRecords(t, expected, actual, recordIDs, sequences[arn])
		}
		if segment.Reopen {
			clients = reopen()
		}
	}
}

func dynamoStreamsBind(t *testing.T, bindings map[string]string, expected, actual map[string]any, field string) {
	t.Helper()
	if native, ok := expected[field].(string); ok {
		local, ok := actual[field].(string)
		if !ok || local == "" {
			t.Fatalf("missing %s in %v", field, actual)
		}
		aasBind(t, bindings, native, local)
	}
}

func dynamoStreamsRecords(t *testing.T, expected, actual []any, ids, sequences map[string]string) {
	t.Helper()
	// Stable sorting only across keys preserves native per-item event ordering
	// without inventing ordering between AWS shards or batch-write items.
	key := func(record any) string {
		encoded, _ := json.Marshal(record.(map[string]any)["dynamodb"].(map[string]any)["Keys"])
		return string(encoded)
	}
	for _, records := range [][]any{expected, actual} {
		slices.SortStableFunc(records, func(a, b any) int {
			return strings.Compare(key(a), key(b))
		})
	}
	if len(expected) != len(actual) {
		t.Fatalf("stream record count %d want %d", len(actual), len(expected))
	}
	for i := range expected {
		want, got := expected[i].(map[string]any), actual[i].(map[string]any)
		dynamoStreamsBind(t, ids, want, got, "eventID")
		want["eventID"] = got["eventID"]
		wantData, gotData := want["dynamodb"].(map[string]any), got["dynamodb"].(map[string]any)
		dynamoStreamsBind(t, sequences, wantData, gotData, "SequenceNumber")
		wantData["SequenceNumber"] = gotData["SequenceNumber"]
		delete(wantData, "ApproximateCreationDateTime")
		delete(gotData, "ApproximateCreationDateTime")
		if want["awsRegion"] == "ddblocal" {
			want["awsRegion"] = "us-east-1"
		}
		dynamoCompare(t, "stream-record", want, got, nil, false)
	}
}
