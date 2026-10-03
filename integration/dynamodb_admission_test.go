package stackd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamotypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"
	streamtypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	dynamoengine "stackd/engine/dynamodb"
	"stackd/internal/awstest"
)

// Pressure stops on the first actual rejection rather than pinning a native
// throttle ordinal. Assertions cover effects, errors, partial outcomes and
// retained metrics; the fixture does not claim AWS's private allocation policy.
func TestDynamoDBAdmissionContracts(t *testing.T) {
	if os.Getenv("STACKD_DYNAMODB_DOCKER") != "1" {
		t.Skip("set STACKD_DYNAMODB_DOCKER=1 to exercise pinned DynamoDB Local")
	}
	var fixture struct {
		Scenarios []struct {
			Name   string
			Tables []json.RawMessage
			Steps  []struct {
				Name, Operation, Code, Advance string
				Input                          json.RawMessage
				UntilThrottled, Reopen         bool
				PartialReadUnits               float64
				Want                           map[string]any
			}
			Metrics []struct {
				Table, Name, Operation, OperationType, Verb, Index string
				Sum                                                float64
			}
			StreamForbidden map[string][]string
		}
	}
	raw, err := os.ReadFile("../testdata/dynamodb/admission.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	runtime, err := dynamoengine.NewDocker(t.Context(), dynamoengine.DockerConfig{Client: engine})
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range fixture.Scenarios {
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(scenario.Name+"/"+backend, func(t *testing.T) {
				start := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
				source := clock.NewManual(start)
				owned := &dynamoReplayRuntime{Runtime: runtime}
				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					defer cancel()
					for _, spec := range owned.specifications() {
						if err := runtime.Remove(ctx, spec); err != nil {
							t.Errorf("remove native database %s: %v", spec.ID, err)
						}
					}
				})
				clients, reopen := retainedCloud(t, backend, stackd.Config{Clock: source, DynamoDBRuntime: owned})
				for _, input := range scenario.Tables {
					client := dynamoClient(clients, "test", "test", clients.server.Client())
					_, err := awstest.CallSDK(t.Context(), client, "CreateTable", json.RawMessage(`{}`), func(target any) { dynamoSDKInput(t, target, input) })
					if err != nil {
						t.Fatal(err)
					}
					table := ecsControlBody(t, input)["TableName"].(string)
					if err := dynamoWaitActive(t.Context(), client, table); err != nil {
						t.Fatal(err)
					}
				}
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
				for _, step := range scenario.Steps {
					if !t.Run(step.Name, func(t *testing.T) {
						if step.Reopen {
							clients = reopen()
						}
						if step.Advance != "" {
							duration, err := time.ParseDuration(step.Advance)
							if err != nil {
								t.Fatal(err)
							}
							advanceClock(t, source, duration)
							trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
						}
						if step.Operation == "" {
							return
						}
						input := json.RawMessage(strings.ReplaceAll(string(step.Input), "$large", strings.Repeat("x", 350*1024)))
						wire := &awstest.WireClient{Client: clients.server.Client()}
						client := dynamoClient(clients, "test", "test", wire)
						attempts := 1
						if step.UntilThrottled {
							attempts = 64
						}
						var output any
						for attempt := 0; attempt < attempts; attempt++ {
							output, err = awstest.CallSDK(t.Context(), client, step.Operation, json.RawMessage(`{}`), func(target any) { dynamoSDKInput(t, target, input) })
							if err != nil || !step.UntilThrottled {
								break
							}
						}
						if step.Code != "" {
							assertAPIError(t, err, step.Code)
						} else if err != nil {
							t.Fatal(err)
						}
						actual := ecsControlBody(t, wire.Body)
						if step.Operation == "UpdateTable" && err == nil {
							table := ecsControlBody(t, input)["TableName"].(string)
							if err := dynamoWaitActive(t.Context(), client, table); err != nil {
								t.Fatal(err)
							}
						}
						if step.PartialReadUnits != 0 {
							advanceClock(t, source, 5*time.Minute)
							trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
							actual = dynamoPartialBatchRead(t, client, wire, input, output.(*dynamodb.BatchGetItemOutput), step.PartialReadUnits)
						}
						selected := make(map[string]any, len(step.Want))
						for field := range step.Want {
							selected[field] = dynamoAdmissionField(t, actual, field)
						}
						if len(step.Want) != 0 {
							dynamoCompare(t, step.Operation, step.Want, selected, nil, true)
						}
					}) {
						return
					}
				}
				for _, metric := range scenario.Metrics {
					dimensions := []metrictypes.Dimension{{Name: aws.String("TableName"), Value: &metric.Table}}
					if metric.Operation != "" {
						dimensions = append(dimensions, metrictypes.Dimension{Name: aws.String("Operation"), Value: &metric.Operation})
					}
					if metric.OperationType != "" {
						dimensions = append(dimensions, metrictypes.Dimension{Name: aws.String("OperationType"), Value: &metric.OperationType})
					}
					if metric.Verb != "" {
						dimensions = append(dimensions, metrictypes.Dimension{Name: aws.String("Verb"), Value: &metric.Verb})
					}
					if metric.Index != "" {
						dimensions = append(dimensions, metrictypes.Dimension{Name: aws.String("GlobalSecondaryIndexName"), Value: &metric.Index})
					}
					dynamoMetricSum(t, metricsClient(clients, "test"), &cloudwatch.GetMetricStatisticsInput{Namespace: aws.String("AWS/DynamoDB"), MetricName: &metric.Name, Dimensions: dimensions, StartTime: &start, EndTime: aws.Time(start.Add(time.Minute)), Period: aws.Int32(60), Statistics: []metrictypes.Statistic{metrictypes.StatisticSum}}, metric.Sum)
				}
				streamClient := dynamodbstreams.New(dynamodbstreams.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				for table, forbidden := range scenario.StreamForbidden {
					sawLargeItem := false
					streams, err := streamClient.ListStreams(t.Context(), &dynamodbstreams.ListStreamsInput{TableName: &table})
					if err != nil {
						t.Fatal(err)
					}
					for _, stream := range streams.Streams {
						described, err := streamClient.DescribeStream(t.Context(), &dynamodbstreams.DescribeStreamInput{StreamArn: stream.StreamArn})
						if err != nil {
							t.Fatal(err)
						}
						for _, shard := range described.StreamDescription.Shards {
							iterator, err := streamClient.GetShardIterator(t.Context(), &dynamodbstreams.GetShardIteratorInput{StreamArn: stream.StreamArn, ShardId: shard.ShardId, ShardIteratorType: streamtypes.ShardIteratorTypeTrimHorizon})
							if err != nil {
								t.Fatal(err)
							}
							for next := iterator.ShardIterator; next != nil; {
								page, err := streamClient.GetRecords(t.Context(), &dynamodbstreams.GetRecordsInput{ShardIterator: next})
								if err != nil {
									t.Fatal(err)
								}
								for _, record := range page.Records {
									if key, ok := record.Dynamodb.NewImage["pk"].(*streamtypes.AttributeValueMemberS); ok && key.Value == "large" {
										sawLargeItem = true
									}
									for _, field := range forbidden {
										if _, exists := record.Dynamodb.NewImage[field]; exists {
											t.Fatalf("rejected %s mutation appeared in Streams field %s", table, field)
										}
									}
								}
								if len(page.Records) == 0 {
									break
								}
								next = page.NextShardIterator
							}
						}
					}
					if !sawLargeItem {
						t.Fatalf("Streams omitted the admitted large item for %s", table)
					}
				}
			})
		}
	}
}

// Select an exact nested contract without copying incidental table metadata into
// fixtures. Array positions are used only where the fixture owns one index.
func dynamoAdmissionField(t *testing.T, value any, path string) any {
	t.Helper()
	for _, part := range strings.Split(path, ".") {
		switch current := value.(type) {
		case map[string]any:
			value = current[part]
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil {
				t.Fatalf("invalid array component %q in %q", part, path)
			}
			if index < 0 || index >= len(current) {
				return nil
			}
			value = current[index]
		default:
			return nil
		}
	}
	return value
}

// Retry the returned request verbatim. This checks projection/consistency
// preservation and accepted-only billing without pinning a throttle ordinal.
func dynamoPartialBatchRead(t *testing.T, client *dynamodb.Client, wire *awstest.WireClient, input json.RawMessage, first *dynamodb.BatchGetItemOutput, units float64) map[string]any {
	t.Helper()
	var request dynamodb.BatchGetItemInput
	dynamoSDKInput(t, &request, input)
	keyID := func(key map[string]dynamotypes.AttributeValue) string {
		encoded, err := json.Marshal(key)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	requested := make(map[string]bool)
	for _, table := range request.RequestItems {
		for _, key := range table.Keys {
			requested[keyID(key)] = true
		}
	}
	pending := make(map[string]bool)
	for _, table := range first.UnprocessedKeys {
		for _, key := range table.Keys {
			id := keyID(key)
			if !requested[id] || pending[id] {
				t.Fatalf("unprocessed key is not a unique requested key: %s", id)
			}
			pending[id] = true
		}
	}
	if len(pending) == 0 || len(pending) == len(requested) {
		t.Fatalf("expected within-table partial admission, got %d unprocessed of %d", len(pending), len(requested))
	}
	checkCapacity := func(out *dynamodb.BatchGetItemOutput, count int) {
		t.Helper()
		var actual float64
		for _, capacity := range out.ConsumedCapacity {
			actual += aws.ToFloat64(capacity.CapacityUnits)
		}
		if expected := float64(count) * units; actual != expected {
			t.Fatalf("processed-key capacity = %v, want %v", actual, expected)
		}
	}
	checkCapacity(first, len(requested)-len(pending))
	combined := ecsControlBody(t, wire.Body)
	retry, err := client.BatchGetItem(t.Context(), &dynamodb.BatchGetItemInput{
		RequestItems: first.UnprocessedKeys, ReturnConsumedCapacity: dynamotypes.ReturnConsumedCapacityIndexes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(retry.UnprocessedKeys) != 0 {
		t.Fatalf("unprocessed retry did not recover: %v", retry.UnprocessedKeys)
	}
	checkCapacity(retry, len(pending))
	retried := ecsControlBody(t, wire.Body)
	responses := combined["Responses"].(map[string]any)
	for table, items := range retried["Responses"].(map[string]any) {
		if previous, ok := responses[table].([]any); ok {
			responses[table] = append(previous, items.([]any)...)
		} else {
			responses[table] = items
		}
	}
	combined["UnprocessedKeys"] = retried["UnprocessedKeys"]
	return combined
}

func TestDynamoDBNativeBatchRequestEnvelope(t *testing.T) {
	var fixture struct {
		Input json.RawMessage
		Calls []struct {
			RequestBytes, HTTPStatus int
			ErrorCode, ResponseBody  string
		}
	}
	dynamoReadJSON(t, "batch_request_size", &fixture)
	clients, _ := retainedCloud(t, "memory", stackd.Config{})
	for _, call := range fixture.Calls {
		body := make([]byte, call.RequestBytes)
		copy(body, fixture.Input)
		for i := len(fixture.Input); i < len(body); i++ {
			body[i] = ' '
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, clients.server.URL, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/x-amz-json-1.0")
		request.Header.Set("X-Amz-Target", "DynamoDB_20120810.BatchWriteItem")
		digest := sha256.Sum256(body)
		if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, request, hex.EncodeToString(digest[:]), "dynamodb", "us-east-1", time.Now()); err != nil {
			t.Fatal(err)
		}
		response, err := clients.server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != call.HTTPStatus {
			t.Fatalf("%d-byte request: HTTP %d, want native %d", call.RequestBytes, response.StatusCode, call.HTTPStatus)
		}
		if call.ResponseBody == "" {
			if len(raw) != 0 {
				t.Fatalf("native empty rejection gained a body: %s", raw)
			}
		} else {
			code, _ := ecsControlBody(t, raw)["__type"].(string)
			if _, suffix, namespaced := strings.Cut(code, "#"); namespaced {
				code = suffix
			}
			if code != call.ErrorCode {
				t.Fatalf("boundary request reached %s, want %s", code, call.ErrorCode)
			}
		}
	}
}
