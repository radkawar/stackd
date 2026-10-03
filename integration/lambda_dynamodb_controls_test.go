package stackd_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	computelambda "stackd/compute/lambda"
	dynamoengine "stackd/engine/dynamodb"
	"stackd/storage"
	lambdastore "stackd/storage/lambda"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

// Replay the capture's ordered control phase, before any records are written.
// Both source admission and function deployment use the real container runtimes.
func TestLambdaDynamoDBMappingDockerNativeControls(t *testing.T) {
	lambdaURLDocker(t)
	if os.Getenv("STACKD_DYNAMODB_DOCKER") != "1" {
		t.Skip("set STACKD_DYNAMODB_DOCKER=1 to exercise pinned DynamoDB Local")
	}
	fixture := lambdaFixture[lambdaDynamoDBFixture](t, "dynamodb_source").lambdaURLFixture
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	runtime, err := dynamoengine.NewDocker(t.Context(), dynamoengine.DockerConfig{Client: engine})
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			observed := &dynamoReplayRuntime{Runtime: runtime}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				for _, spec := range observed.specifications() {
					if err := runtime.Remove(ctx, spec); err != nil {
						t.Errorf("remove native database %s: %v", spec.ID, err)
					}
				}
			})
			source := clock.NewManual(fixture.StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{Clock: source, DynamoDBRuntime: observed},
				func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					return newLambdaDockerStack(t, config, &computelambda.DockerConfig{Client: engine})
				})
			var lambdaClient *awslambda.Client
			connect := func() {
				lambdaClient = awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			connect()
			account := fixture.row(t, "identity_before_writes").Result.Output["Account"].(string)
			replacements := []string{account, "000000000000"}
			normalize := func() *strings.Replacer { return strings.NewReplacer(replacements...) }
			settle := func() {
				advanceClock(t, source, time.Second)
				cloud := clients.server.Config.Handler.(*stackd.Stack)
				if _, err := cloud.RunDueJobs(t.Context(), 256); err != nil {
					t.Fatal(err)
				}
			}
			replayMapping := func(t *testing.T, row lambdaURLRow) {
				t.Helper()
				input := lambdaStreamingInput[map[string]any](t, row.Input, normalize())
				if seconds, ok := input["StartingPositionTimestamp"].(float64); ok {
					input["StartingPositionTimestamp"] = time.Unix(0, int64(seconds*float64(time.Second))).UTC().Format(time.RFC3339Nano)
				}
				operation := lambdaSQSControlOperations(lambdaClient)[row.Operation]
				if operation == nil {
					t.Fatalf("missing mapping operation %s", row.Operation)
				}
				actual, err := operation(t.Context(), input)
				if row.Result.Code != "Success" {
					assertAPIError(t, err, row.Result.Code)
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if row.Operation == "create-event-source-mapping" {
					replacements = append(replacements, row.Result.Output["UUID"].(string), actual["UUID"].(string))
				}
				expected := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, row.Result.Output), normalize())
				var comparable func(map[string]any)
				comparable = func(value map[string]any) {
					// Compare decoded SDK results to the decoded CLI capture, not raw JSON nulls.
					lambdaPolicyComparable(t, value)
					delete(value, "ResponseMetadata")
					if rows, ok := value["EventSourceMappings"].([]any); ok {
						for _, row := range rows {
							comparable(row.(map[string]any))
						}
					}
				}
				comparable(actual)
				comparable(expected)
				if !reflect.DeepEqual(actual, expected) {
					t.Fatalf("control response\ngot  %s\nwant %s", lambdaQualifiedJSON(t, actual), lambdaQualifiedJSON(t, expected))
				}
			}
			reachedEnd := false
			for _, row := range fixture.Observations {
				// The capture's first data write marks the next independently replayed phase.
				if row.Label == "tumbling_enable" {
					reachedEnd = true
					break
				}
				if row.Service == "sts" || row.Service == "logs" || row.Operation == "describe-table" || row.Operation == "get-function-configuration" || row.Result.Code == "ParamValidation" {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) {
					if strings.HasSuffix(row.Operation, "event-source-mapping") || row.Operation == "list-event-source-mappings" {
						if row.Operation == "get-event-source-mapping" {
							settle()
						}
						replayMapping(t, row)
						if row.Label == "stream_settings_admission_ready_0" || row.Label == "tumbling_created_0" {
							clients = reopen()
							connect()
							replayMapping(t, row)
						}
						return
					}
					switch row.Operation {
					case "create-role":
						input := lambdaStreamingInput[iam.CreateRoleInput](t, row.Input, normalize())
						_, err = clients.iam("test", "test", "").CreateRole(t.Context(), &input)
					case "put-role-policy":
						input := lambdaStreamingInput[iam.PutRolePolicyInput](t, row.Input, normalize())
						_, err = clients.iam("test", "test", "").PutRolePolicy(t.Context(), &input)
					case "create-table":
						input := lambdaStreamingInput[dynamodb.CreateTableInput](t, row.Input, normalize())
						client := dynamoClient(clients, "test", "test", clients.server.Client())
						_, err = client.CreateTable(t.Context(), &input)
						if err == nil {
							err = dynamoWaitActive(t.Context(), client, aws.ToString(input.TableName))
						}
						if err == nil {
							out, e := client.DescribeTable(t.Context(), &dynamodb.DescribeTableInput{TableName: input.TableName})
							err = e
							if err == nil {
								native := row.Result.Output["TableDescription"].(map[string]any)["LatestStreamArn"].(string)
								replacements = append([]string{native, aws.ToString(out.Table.LatestStreamArn)}, replacements...)
							}
						}
					case "create-queue":
						input := lambdaStreamingInput[sqs.CreateQueueInput](t, row.Input, normalize())
						var out *sqs.CreateQueueOutput
						out, err = clients.sqs("test", "test", "").CreateQueue(t.Context(), &input)
						if err == nil {
							replacements = append([]string{row.Result.Output["QueueUrl"].(string), aws.ToString(out.QueueUrl)}, replacements...)
						}
					case "get-queue-attributes":
						input := lambdaStreamingInput[sqs.GetQueueAttributesInput](t, row.Input, normalize())
						_, err = clients.sqs("test", "test", "").GetQueueAttributes(t.Context(), &input)
					default:
						input := lambdaStreamingInput[map[string]any](t, row.Input, normalize())
						operation := lambdaSQSControlOperations(lambdaClient)[row.Operation]
						if operation == nil {
							t.Fatalf("unclassified native prerequisite %s", row.Operation)
						}
						_, err = operation(t.Context(), input)
						if err == nil && row.Operation == "create-function" {
							name := input["FunctionName"].(string)
							err = awslambda.NewFunctionActiveWaiter(lambdaClient, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute)
						}
					}
					if err != nil {
						t.Fatal(err)
					}
				}) {
					t.FailNow()
				}
			}
			if !reachedEnd {
				t.Fatal("native control phase boundary missing")
			}
		})
	}
}

// Control writes preserve worker results, while deletion releases source state
// and prevents a late completion from resurrecting it across retained stores.
func TestLambdaDynamoDBMappingRetainedOwnership(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "stream-mapping.sqlite")
			closeDB := func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			defer func() { closeDB() }()
			key := lambdastore.EventSourceMappingKey{Scope: lambdastore.Scope{Partition: "aws", Account: "000000000000", Region: "us-east-1"}, UUID: "d732e449-46d8-4216-9693-e1a3e061bbf3"}
			record := lambdastore.EventSourceMappingRecord{
				Key:            key,
				Function:       lambdastore.FunctionReference{FunctionKey: lambdastore.FunctionKey{Scope: key.Scope, Name: "function"}},
				EventSourceARN: "arn:aws:dynamodb:us-east-1:000000000000:table/example/stream/2026-09-17T00:00:00.000",
				Version:        1, State: "Enabled", LastProcessingResult: "No records processed",
				Settings: lambdastore.EventSourceMappingSettings{BatchSize: 100, Stream: &lambdastore.StreamMappingSettings{
					StartingPosition: "LATEST", ParallelizationFactor: 1, MaximumRetryAttempts: -1, MaximumRecordAge: -time.Second,
				}},
			}
			if err := backends.Lambda.Update(t.Context(), func(tx lambdastore.Transaction) error { return tx.PutEventSourceMapping(record) }); err != nil {
				t.Fatal(err)
			}
			var stale lambdastore.EventSourceMappingRecord
			if err := backends.Lambda.View(t.Context(), func(tx lambdastore.Reader) error { var err error; stale, err = tx.EventSourceMapping(key); return err }); err != nil {
				t.Fatal(err)
			}
			if err := backends.Lambda.Update(t.Context(), func(tx lambdastore.Transaction) error { return tx.SetEventSourceMappingProcessingResult(key, "OK") }); err != nil {
				t.Fatal(err)
			}
			stale.Tags = map[string]string{"owner": "control"}
			if err := backends.Lambda.Update(t.Context(), func(tx lambdastore.Transaction) error { return tx.PutEventSourceMapping(stale) }); err != nil {
				t.Fatal(err)
			}
			if backend == "sqlite" {
				closeDB()
				backends, closeDB = openSQLiteBackends(t, path)
			}
			if err := backends.Lambda.View(t.Context(), func(tx lambdastore.Reader) error {
				got, err := tx.EventSourceMapping(key)
				if err != nil {
					return err
				}
				if got.LastProcessingResult != "OK" || got.Tags["owner"] != "control" {
					t.Fatalf("concurrent worker status or control tags lost: status=%q tags=%v", got.LastProcessingResult, got.Tags)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			shard := lambdastore.StreamShardRecord{
				Key:   lambdastore.StreamShardKey{Mapping: key, ShardID: "source-shard"},
				Lanes: []lambdastore.StreamLane{{WindowState: []byte(`{"count":2}`)}},
			}
			if err := backends.Lambda.Update(t.Context(), func(tx lambdastore.Transaction) error { return tx.PutStreamShard(shard) }); err != nil {
				t.Fatal(err)
			}
			if err := backends.Lambda.Update(t.Context(), func(tx lambdastore.Transaction) error { return tx.DeleteEventSourceMapping(key) }); err != nil {
				t.Fatal(err)
			}
			if err := backends.Lambda.Update(t.Context(), func(tx lambdastore.Transaction) error { return tx.PutStreamShard(shard) }); !errors.Is(err, lambdastore.ErrNotFound) {
				t.Fatalf("late completion after mapping deletion: got %v, want ErrNotFound", err)
			}
			if backend == "sqlite" {
				closeDB()
				backends, closeDB = openSQLiteBackends(t, path)
			}
			if err := backends.Lambda.View(t.Context(), func(tx lambdastore.Reader) error {
				shards, err := tx.StreamShards(key)
				if len(shards) != 0 {
					t.Fatalf("deleted mapping retained %d source shards", len(shards))
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
