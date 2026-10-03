package stackd_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd"
	"stackd/clock"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type lambdaDynamoDBInvocation struct {
	RequestID  string         `json:"request_id"`
	InvokedARN string         `json:"invoked_arn"`
	Event      map[string]any `json:"event"`
	Response   map[string]any `json:"response"`
	Error      map[string]any `json:"error"`
	Time       float64        `json:"time"`
}
type lambdaDynamoDBFixture struct {
	lambdaURLFixture
	Delivery map[string]struct {
		Invocations []lambdaDynamoDBInvocation `json:"invocations"`
	} `json:"delivery"`
	DestinationMessages []struct {
		Body string
	} `json:"destination_messages"`
	MaximumAgeHold struct {
		Seconds int64 `json:"seconds"`
	} `json:"maximum_age_hold"`
}

// This replays captured writes into DynamoDB Local and deploys the captured ZIP
// into the ordinary Lambda Docker executor. Neither source nor execution is a
// fake. Reopen deliberately falls between a failed parent and its retained retry.
func TestLambdaDynamoDBDockerNativeDeliveryAndRecovery(t *testing.T) {
	lambdaDynamoDBDocker(t)
	fixture := lambdaFixture[lambdaDynamoDBFixture](t, "dynamodb_source")
	for _, backend := range []string{"memory", "sqlite"} {
		for _, label := range []string{"images", "filter", "batch_size", "window", "partial_disabled", "partial_enabled", "partial_bisect", "raise_retry", "invalid_partial", "raise_bisect", "tumbling", "maximum_age"} {
			native, exists := fixture.Delivery[label]
			t.Run(backend+"/"+label, func(t *testing.T) {
				if !exists {
					t.Fatalf("native capture has no delivery evidence for %s", label)
				}
				source := clock.NewManual(fixture.StartedAt)
				clients, reopen := lambdaDynamoDBCloud(t, backend, source)
				replacements := []string{fixture.row(t, "identity_before_writes").Result.Output["Account"].(string), "000000000000"}
				replace := func() *strings.Replacer { return strings.NewReplacer(replacements...) }
				call := func(row lambdaURLRow) any {
					return lambdaDynamoDBCall(t, clients, row, replace())
				}
				call(fixture.row(t, "create_log_group"))
				call(fixture.row(t, "create_role"))
				tableInput := lambdaStreamingInput[dynamodb.CreateTableInput](t, fixture.row(t, "create_table").Input, replace())
				call(fixture.row(t, "create_table"))
				ddb := dynamoClient(clients, "test", "test", clients.server.Client())
				if err := dynamoWaitActive(t.Context(), ddb, aws.ToString(tableInput.TableName)); err != nil {
					t.Fatal(err)
				}
				table, err := ddb.DescribeTable(t.Context(), &dynamodb.DescribeTableInput{TableName: tableInput.TableName})
				if err != nil {
					t.Fatal(err)
				}
				nativeStream := fixture.row(t, label+"_configure").Input
				var mappingInput awslambda.CreateEventSourceMappingInput
				if err := json.Unmarshal(nativeStream, &mappingInput); err != nil {
					t.Fatal(err)
				}
				replacements = append([]string{aws.ToString(mappingInput.EventSourceArn), aws.ToString(table.Table.LatestStreamArn)}, replacements...)
				queue := call(fixture.row(t, "create_destination")).(*sqs.CreateQueueOutput)
				replacements = append([]string{fixture.row(t, "create_destination").Result.Output["QueueUrl"].(string), aws.ToString(queue.QueueUrl)}, replacements...)
				for _, row := range fixture.Observations {
					if strings.HasPrefix(row.Label, "policy_owned-") && row.Operation == "put-role-policy" && row.Result.Code == "Success" {
						call(row)
					}
				}
				for _, row := range fixture.Observations {
					if row.Operation == "create-function" && row.Result.Code == "Success" {
						call(row)
						break
					}
				}
				if err := awslambda.NewFunctionActiveWaiter(lambdaDynamoDBClient(clients), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &fixture.Prefix}, time.Minute); err != nil {
					t.Fatal(err)
				}
				call(fixture.row(t, "publish_handler"))
				call(fixture.row(t, label+"_alias"))
				mappingID := call(fixture.row(t, label+"_configure")).(map[string]any)["UUID"].(string)
				for _, row := range fixture.Observations {
					if label == "tumbling" && row.Label == "tumbling_put_5" {
						continue
					}
					if strings.HasPrefix(row.Label, label+"_") && (row.Operation == "put-item" || row.Operation == "delete-item" || row.Operation == "update-item") {
						call(row)
					}
				}
				// Reopen before delivery also proves LATEST/TRIM configuration and ordinary
				// source history belong to their own persistent domains, not a live fixture.
				clients = reopen()
				if label == "maximum_age" {
					advanceClock(t, source, time.Duration(fixture.MaximumAgeHold.Seconds)*time.Second)
				}
				advanceClock(t, source, time.Second)
				if _, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 256); err != nil {
					t.Fatal(err)
				}
				if _, err := lambdaDynamoDBClient(clients).UpdateEventSourceMapping(t.Context(), &awslambda.UpdateEventSourceMappingInput{UUID: &mappingID, Enabled: aws.Bool(true)}); err != nil {
					t.Fatal(err)
				}
				want := native.Invocations
				nativeMappingID := fixture.row(t, label+"_configure").Result.Output["UUID"]
				var wantProcessingResult, processingResult string
				for _, row := range fixture.Observations {
					if row.Result.Output["UUID"] == nativeMappingID {
						if status, ok := row.Result.Output["LastProcessingResult"].(string); ok {
							wantProcessingResult = status
						}
					}
				}
				var got []lambdaDynamoDBInvocation
				reopened := false
				fifthWritten := false
				deadline := time.Now().Add(90 * time.Second)
				for time.Now().Before(deadline) {
					advanceClock(t, source, 250*time.Millisecond)
					got = lambdaDynamoDBLogInvocations(t, clients, fixture.Prefix, "DDB_PROBE ")
					if !reopened && (label == "partial_enabled" || label == "partial_bisect" || label == "raise_retry" || label == "tumbling") && len(got) > 0 {
						state, err := lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &mappingID})
						if err != nil {
							t.Fatal(err)
						}
						if aws.ToString(state.LastProcessingResult) != "No records processed" {
							clients = reopen()
							reopened = true
						}
					}
					if label == "tumbling" && len(got) >= 4 && !fifthWritten {
						advanceClock(t, source, time.Duration(aws.ToInt32(mappingInput.TumblingWindowInSeconds))*time.Second)
						call(fixture.row(t, "tumbling_put_5"))
						fifthWritten = true
					}
					if len(got) >= len(want) {
						state, err := lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &mappingID})
						if err != nil {
							t.Fatal(err)
						}
						processingResult = aws.ToString(state.LastProcessingResult)
						if processingResult == wantProcessingResult {
							break
						}
					}
					time.Sleep(50 * time.Millisecond)
				}
				if len(got) != len(want) {
					t.Fatalf("runtime invocations=%d native=%d: %+v", len(got), len(want), got)
				}
				if processingResult != wantProcessingResult {
					t.Fatalf("processing result=%q native=%q", processingResult, wantProcessingResult)
				}
				for i := range want {
					expected := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, want[i].Event), replace())
					actual := lambdaDynamoDBComparableEvent(t, got[i].Event)
					expected = lambdaDynamoDBComparableEvent(t, expected)
					if !reflect.DeepEqual(actual, expected) {
						t.Fatalf("invocation %d payload\ngot %s\nwant %s", i, lambdaQualifiedJSON(t, actual), lambdaQualifiedJSON(t, expected))
					}
					for j := range i {
						if (got[i].RequestID == got[j].RequestID) != (want[i].RequestID == want[j].RequestID) {
							t.Fatalf("retry request identity relation changed for invocations %d,%d", j, i)
						}
					}
				}
				lambdaDynamoDBDestinationEvidence(t, clients, source, queue.QueueUrl, fixture, label, replace())
				if len(want) == 0 {
					if got := lambdaDynamoDBLogInvocations(t, clients, fixture.Prefix, "DDB_PROBE "); len(got) != 0 {
						t.Fatalf("discarded records reached the runtime: %+v", got)
					}
				}
			})
		}
	}
}
func lambdaDynamoDBLogInvocations(t *testing.T, clients cloudClients, name, marker string) []lambdaDynamoDBInvocation {
	t.Helper()
	group := "/aws/lambda/" + name
	var result []lambdaDynamoDBInvocation
	var next *string
	for {
		output, err := logsClient(clients, "test").FilterLogEvents(t.Context(), &cloudwatchlogs.FilterLogEventsInput{LogGroupName: &group, NextToken: next})
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range output.Events {
			text := aws.ToString(event.Message)
			start := strings.Index(text, marker)
			if start < 0 {
				continue
			}
			var invocation lambdaDynamoDBInvocation
			if err := json.Unmarshal([]byte(strings.TrimSpace(text[start+len(marker):])), &invocation); err != nil {
				t.Fatal(err)
			}
			result = append(result, invocation)
		}
		if aws.ToString(output.NextToken) == "" || aws.ToString(output.NextToken) == aws.ToString(next) {
			return result
		}
		next = output.NextToken
	}
}
func lambdaDynamoDBComparableEvent(t *testing.T, event map[string]any) map[string]any {
	t.Helper()
	var cloned map[string]any
	if err := json.Unmarshal(lambdaQualifiedJSON(t, event), &cloned); err != nil {
		t.Fatal(err)
	}
	delete(cloned, "shardId")
	if window, ok := cloned["window"].(map[string]any); ok {
		start, err := time.Parse(time.RFC3339Nano, window["start"].(string))
		if err != nil {
			t.Fatal(err)
		}
		end, err := time.Parse(time.RFC3339Nano, window["end"].(string))
		if err != nil {
			t.Fatal(err)
		}
		cloned["window"] = map[string]any{"duration": end.Sub(start).Seconds()}
	}
	for _, item := range cloned["Records"].([]any) {
		record := item.(map[string]any)
		delete(record, "eventID")
		data := record["dynamodb"].(map[string]any)
		delete(data, "SequenceNumber")
		delete(data, "ApproximateCreationDateTime")
	}
	return cloned
}
func lambdaDynamoDBDestinationEvidence(t *testing.T, clients cloudClients, source *clock.Manual, queue *string, fixture lambdaDynamoDBFixture, label string, replace *strings.Replacer) {
	t.Helper()
	var expected map[string]any
	for _, message := range fixture.DestinationMessages {
		document := lambdaStreamingInput[map[string]any](t, []byte(message.Body), replace)
		context := document["requestContext"].(map[string]any)
		if strings.HasSuffix(context["functionArn"].(string), ":"+label) {
			expected = document
			break
		}
	}
	if expected == nil {
		return
	}
	var actual map[string]any
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		advanceClock(t, source, time.Second)
		output, err := clients.sqs("test", "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue, MaxNumberOfMessages: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(output.Messages) > 0 {
			if err := json.Unmarshal([]byte(aws.ToString(output.Messages[0].Body)), &actual); err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if actual == nil {
		t.Fatal("native discarded-batch destination was not delivered")
	}
	for _, doc := range []map[string]any{actual, expected} {
		delete(doc, "timestamp")
		delete(doc["requestContext"].(map[string]any), "requestId")
		info := doc["DDBStreamBatchInfo"].(map[string]any)
		for _, field := range []string{"shardId", "startSequenceNumber", "endSequenceNumber", "approximateArrivalOfFirstRecord", "approximateArrivalOfLastRecord"} {
			delete(info, field)
		}
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("destination\ngot %s\nwant %s", lambdaQualifiedJSON(t, actual), lambdaQualifiedJSON(t, expected))
	}
}
