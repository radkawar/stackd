package stackd_test

import (
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"stackd"
	"stackd/clock"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type lambdaDynamoDBWindowFixture struct {
	lambdaURLFixture
	Cases map[string]struct {
		StreamARN string `json:"stream_arn"`
		Timeline  []struct {
			Stage               string
			InvocationsObserved int `json:"invocations_observed"`
		} `json:"timeline"`
		Invocations []struct {
			LogEventRef string `json:"log_event_ref"`
		} `json:"invocations"`
		S3ObjectKeys []string `json:"s3_object_keys"`
	} `json:"cases"`
	LogEvents map[string]struct {
		Message string
	} `json:"log_events"`
	Blobs     map[string]string `json:"blobs"`
	S3Objects map[string]struct {
		BodyUTF8 string `json:"body_utf8"`
		Metadata struct {
			ContentType string
		}
	} `json:"s3_objects"`
}

// Replay the captured ZIP, including its lossless evidence-only blob encoding.
// The counts are phase barriers from the native timeline, not latency or
// exactly-once guarantees. In particular, no idle nonobservation is asserted.
func TestLambdaDynamoDBDockerNativeWindows(t *testing.T) {
	lambdaDynamoDBDocker(t)
	fixture := lambdaFixture[lambdaDynamoDBWindowFixture](t, "dynamodb_windows")
	for _, backend := range []string{"memory", "sqlite"} {
		for _, label := range []string{"final_failure", "oversized"} {
			t.Run(backend+"/"+label, func(t *testing.T) {
				native, exists := fixture.Cases[label]
				if !exists || len(native.Invocations) == 0 {
					t.Fatalf("missing native window evidence for %s", label)
				}
				source := clock.NewManual(fixture.StartedAt)
				clients, _ := lambdaDynamoDBCloud(t, backend, source)
				replacements := []string{fixture.row(t, "identity_before_writes").Result.Output["Account"].(string), "000000000000"}
				replace := func() *strings.Replacer { return strings.NewReplacer(replacements...) }
				call := func(row lambdaURLRow) any {
					return lambdaDynamoDBCall(t, clients, row, replace())
				}
				for _, prerequisite := range []string{"create_logs", "create_role", "create_bucket", label + "_create_table"} {
					call(fixture.row(t, prerequisite))
				}
				tableInput := lambdaStreamingInput[dynamodb.CreateTableInput](t, fixture.row(t, label+"_create_table").Input, replace())
				ddb := dynamoClient(clients, "test", "test", clients.server.Client())
				if err := dynamoWaitActive(t.Context(), ddb, aws.ToString(tableInput.TableName)); err != nil {
					t.Fatal(err)
				}
				table, err := ddb.DescribeTable(t.Context(), &dynamodb.DescribeTableInput{TableName: tableInput.TableName})
				if err != nil {
					t.Fatal(err)
				}
				replacements = append([]string{native.StreamARN, aws.ToString(table.Table.LatestStreamArn)}, replacements...)
				call(fixture.row(t, "policy_owned-access"))
				created := false
				for _, row := range fixture.Observations {
					if row.Operation == "create-function" && row.Result.Code == "Success" {
						call(row)
						created = true
						break
					}
				}
				if !created {
					t.Fatal("native capture has no successful captured ZIP deployment")
				}
				if err := awslambda.NewFunctionActiveWaiter(lambdaDynamoDBClient(clients), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &fixture.Prefix}, time.Minute); err != nil {
					t.Fatal(err)
				}
				call(fixture.row(t, "publish_handler"))
				call(fixture.row(t, label+"_alias"))
				mappingRow := fixture.row(t, label+"_create_mapping")
				mappingInput := lambdaStreamingInput[awslambda.CreateEventSourceMappingInput](t, mappingRow.Input, replace())
				windowSize := time.Duration(aws.ToInt32(mappingInput.TumblingWindowInSeconds)) * time.Second
				if windowSize <= 0 {
					t.Fatal("native window size must be positive")
				}
				mappingID := call(mappingRow).(map[string]any)["UUID"].(string)
				want := make([]lambdaDynamoDBInvocation, len(native.Invocations))
				for i, reference := range native.Invocations {
					entry, ok := fixture.LogEvents[reference.LogEventRef]
					_, evidence, marked := strings.Cut(entry.Message, "DDB_WINDOW_PROBE ")
					if !ok || !marked {
						t.Fatalf("missing canonical invocation log %s", reference.LogEventRef)
					}
					want[i] = lambdaStreamingInput[lambdaDynamoDBInvocation](t, []byte(evidence), replace())
					lambdaDynamoDBWindowExpand(t, want[i].Event, fixture.Blobs)
					lambdaDynamoDBWindowExpand(t, want[i].Response, fixture.Blobs)
				}
				phaseCount := func(stage string) int {
					for _, phase := range native.Timeline {
						if phase.Stage == stage && phase.InvocationsObserved > 0 {
							return phase.InvocationsObserved
						}
					}
					t.Fatalf("missing native timeline stage %s", stage)
					return 0
				}
				awaitPhase := func(stage string) []lambdaDynamoDBInvocation {
					count := phaseCount(stage)
					deadline := time.Now().Add(90 * time.Second)
					var got []lambdaDynamoDBInvocation
					for time.Now().Before(deadline) {
						advanceClock(t, source, 250*time.Millisecond)
						if _, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 256); err != nil {
							t.Fatal(err)
						}
						got = lambdaDynamoDBLogInvocations(t, clients, fixture.Prefix, "DDB_WINDOW_PROBE ")
						if len(got) >= count {
							return got
						}
						time.Sleep(50 * time.Millisecond)
					}
					t.Fatalf("%s: observed %d runtime invocations, native phase requires %d", stage, len(got), count)
					return nil
				}
				call(fixture.row(t, label+"_put_1"))
				if label == "final_failure" {
					call(fixture.row(t, label+"_put_2"))
				}
				awaitPhase("initial_delivery")
				// Advance source time before each later write; record timestamps, not
				// handler wall time, establish the next tumbling window.
				advanceClock(t, source, windowSize)
				call(fixture.row(t, label+"_put_3"))
				awaitPhase("later_window_record")
				advanceClock(t, source, windowSize)
				call(fixture.row(t, label+"_put_4"))
				got := awaitPhase("second_recovery_record")
				if len(got) < len(want) {
					t.Fatalf("native final phase has %d invocations, got %d", len(want), len(got))
				}
				for i, expected := range want {
					lambdaDynamoDBWindowExpand(t, got[i].Event, fixture.Blobs)
					lambdaDynamoDBWindowExpand(t, got[i].Response, fixture.Blobs)
					actualEvent := lambdaDynamoDBWindowComparableEvent(t, got[i].Event)
					expectedEvent := lambdaDynamoDBWindowComparableEvent(t, expected.Event)
					if !reflect.DeepEqual(actualEvent, expectedEvent) {
						t.Fatalf("invocation %d event differs from canonical native log: got %s want %s", i, lambdaQualifiedJSON(t, actualEvent), lambdaQualifiedJSON(t, expectedEvent))
					}
					if !reflect.DeepEqual(got[i].Response, expected.Response) || !reflect.DeepEqual(got[i].Error, expected.Error) {
						t.Fatalf("invocation %d response/error differs from canonical native log: got %s/%s want %s/%s", i, lambdaQualifiedJSON(t, got[i].Response), lambdaQualifiedJSON(t, got[i].Error), lambdaQualifiedJSON(t, expected.Response), lambdaQualifiedJSON(t, expected.Error))
					}
					if got[i].InvokedARN != expected.InvokedARN {
						t.Fatalf("invocation %d ARN=%s native=%s", i, got[i].InvokedARN, expected.InvokedARN)
					}
					for j := range i {
						if reflect.DeepEqual(got[i].Event["window"], got[j].Event["window"]) != reflect.DeepEqual(expected.Event["window"], want[j].Event["window"]) {
							t.Fatalf("invocations %d,%d lost their native same-window relationship", j, i)
						}
					}
				}
				for _, key := range native.S3ObjectKeys {
					object, ok := fixture.S3Objects[key]
					if !ok {
						t.Fatalf("missing original native S3 object %s", key)
					}
					bucket := lambdaStreamingInput[s3.CreateBucketInput](t, fixture.row(t, "create_bucket").Input, replace())
					lambdaDynamoDBWindowDestination(t, clients, source, aws.ToString(bucket.Bucket), mappingID, object.BodyUTF8, object.Metadata.ContentType, got, replace())
				}
			})
		}
	}
}

func lambdaDynamoDBWindowExpand(t *testing.T, value any, blobs map[string]string) any {
	t.Helper()
	switch value := value.(type) {
	case map[string]any:
		if reference, ok := value["probe_blob_ref"]; ok {
			name, stringReference := reference.(string)
			blob, exists := blobs[name]
			if !stringReference || !exists || len(value) != 1 {
				t.Fatalf("invalid native evidence blob reference %v", value)
			}
			return blob
		}
		for key, item := range value {
			value[key] = lambdaDynamoDBWindowExpand(t, item, blobs)
		}
	case []any:
		for i, item := range value {
			value[i] = lambdaDynamoDBWindowExpand(t, item, blobs)
		}
	}
	return value
}

func lambdaDynamoDBWindowComparableEvent(t *testing.T, event map[string]any) map[string]any {
	t.Helper()
	// Validate fields erased by the common identity/time normalizer so their
	// omission cannot accidentally match the native event.
	if shard, ok := event["shardId"].(string); !ok || shard == "" {
		t.Fatal("window event has no shardId")
	}
	window, ok := event["window"].(map[string]any)
	if !ok || len(window) != 2 {
		t.Fatalf("window must retain exactly start/end: %v", event["window"])
	}
	for _, field := range []string{"start", "end"} {
		text, ok := window[field].(string)
		if _, err := time.Parse(time.RFC3339Nano, text); !ok || err != nil {
			t.Fatalf("invalid window %s: %v", field, window[field])
		}
	}
	records, ok := event["Records"].([]any)
	if !ok {
		t.Fatalf("window Records must be an array, got %T", event["Records"])
	}
	for _, item := range records {
		record := item.(map[string]any)
		data := record["dynamodb"].(map[string]any)
		if id, ok := record["eventID"].(string); !ok || id == "" {
			t.Fatal("DynamoDB record has no eventID")
		}
		if sequence, ok := data["SequenceNumber"].(string); !ok || sequence == "" {
			t.Fatal("DynamoDB record has no SequenceNumber")
		}
		if _, ok := data["ApproximateCreationDateTime"].(float64); !ok {
			t.Fatal("DynamoDB record has no numeric ApproximateCreationDateTime")
		}
	}
	return lambdaDynamoDBComparableEvent(t, event)
}

func lambdaDynamoDBWindowDestination(t *testing.T, clients cloudClients, source *clock.Manual, bucket, mappingID, body, contentType string, invocations []lambdaDynamoDBInvocation, replace *strings.Replacer) {
	t.Helper()
	expected := lambdaStreamingInput[map[string]any](t, []byte(body), replace)
	client := s3NativeClient(clients, "test", "test")
	var key string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		advanceClock(t, source, 250*time.Millisecond)
		if _, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 256); err != nil {
			t.Fatal(err)
		}
		listing, err := client.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: aws.String("aws/lambda/" + mappingID + "/")})
		if err != nil {
			t.Fatal(err)
		}
		if len(listing.Contents) > 0 {
			key = aws.ToString(listing.Contents[0].Key)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if key == "" {
		t.Fatal("failed empty final invocation did not deliver its native S3 document")
	}
	object, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatal(err)
	}
	defer object.Body.Close()
	data, err := io.ReadAll(object.Body)
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(object.ContentType) != contentType {
		t.Fatalf("S3 content type=%q native=%q", aws.ToString(object.ContentType), contentType)
	}
	var actual map[string]any
	if err := json.Unmarshal(data, &actual); err != nil {
		t.Fatal(err)
	}
	for index, document := range []map[string]any{actual, expected} {
		payloadText, ok := document["payload"].(string)
		if !ok {
			t.Fatalf("S3 payload must remain a JSON string, got %T", document["payload"])
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(payloadText), &payload); err != nil {
			t.Fatal(err)
		}
		context := document["requestContext"].(map[string]any)
		info := document["DDBStreamBatchInfo"].(map[string]any)
		windowInfo := document["timeWindowInfo"].(map[string]any)
		if len(info) != 2 || info["shardId"] != payload["shardId"] || info["streamArn"] != payload["eventSourceARN"] {
			t.Fatalf("empty-final DDBStreamBatchInfo must contain only matching shardId/streamArn: %v", info)
		}
		for _, field := range []string{"window", "isFinalInvokeForWindow", "isWindowTerminatedEarly"} {
			if !reflect.DeepEqual(windowInfo[field], payload[field]) {
				t.Fatalf("destination timeWindowInfo.%s differs from original payload", field)
			}
		}
		stamp, ok := document["timestamp"].(string)
		completed, err := time.Parse(time.RFC3339Nano, stamp)
		if !ok || err != nil {
			t.Fatalf("destination timestamp is not RFC3339: %v", document["timestamp"])
		}
		if id, ok := context["requestId"].(string); !ok || id == "" {
			t.Fatal("destination has no requestId")
		}
		if index == 0 {
			matched := false
			for _, invocation := range invocations {
				if invocation.RequestID == context["requestId"] && invocation.Error != nil && reflect.DeepEqual(invocation.Event, payload) {
					matched = true
					break
				}
			}
			if !matched {
				t.Fatal("destination did not retain the failed runtime invocation's request identity and complete event")
			}
			prefix := "aws/lambda/" + mappingID + "/" + info["shardId"].(string) + "/" + completed.UTC().Format("2006/01/02/2006-01-02T15.04.05-")
			if !strings.HasPrefix(key, prefix) || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(strings.TrimPrefix(key, prefix)) {
				t.Fatalf("S3 key does not have the native mapping/shard/date/timestamp/UUID shape: %q", key)
			}
		}
		normalized := lambdaDynamoDBWindowComparableEvent(t, payload)
		document["payload"] = normalized
		windowInfo["window"] = normalized["window"]
		info["shardId"] = "<generated>"
		context["requestId"] = "<generated>"
		document["timestamp"] = "<generated>"
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("S3 document differs from original native UTF8 object: got %s want %s", lambdaQualifiedJSON(t, actual), lambdaQualifiedJSON(t, expected))
	}
}
