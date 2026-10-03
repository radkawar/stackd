package stackd_test

import (
	"reflect"
	"testing"
	"time"

	"stackd/clock"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// Exercise the documented idle-window finalization with a real state-returning
// handler. Reopen is deliberately after a committed response but before the
// empty final invocation; a later record must start with a fresh state object.
func TestLambdaKinesisDockerRetainedWindow(t *testing.T) {
	lambdaURLDocker(t)
	fixture := lambdaFixture[lambdaKinesisFixture](t, "kinesis_source")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.StartedAt)
			clients, reopen := lambdaKinesisCloud(t, backend, source)
			_, streamARN := lambdaKinesisNativeSetup(t, fixture, clients, source)
			code := lambdaZIP(t, map[string]string{"entry.py": `import json
def invoke(event, context):
    count = event.get('state', {}).get('count', 0) + len(event['Records'])
    response = {'state': {'count': count}}
    print('KINESIS_WINDOW ' + json.dumps({'request_id': context.aws_request_id, 'event': event, 'response': response}), flush=True)
    return response
`})
			if _, err := lambdaDynamoDBClient(clients).UpdateFunctionCode(t.Context(), &awslambda.UpdateFunctionCodeInput{FunctionName: &fixture.Prefix, ZipFile: code}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionUpdatedWaiter(lambdaDynamoDBClient(clients), fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &fixture.Prefix}, time.Minute); err != nil {
				t.Fatal(err)
			}
			mapping, err := lambdaDynamoDBClient(clients).CreateEventSourceMapping(t.Context(), &awslambda.CreateEventSourceMappingInput{FunctionName: &fixture.Prefix, EventSourceArn: &streamARN, StartingPosition: lambdatypes.EventSourcePositionTrimHorizon, Enabled: aws.Bool(false), BatchSize: aws.Int32(1), TumblingWindowInSeconds: aws.Int32(10)})
			if err != nil {
				t.Fatal(err)
			}
			id := aws.ToString(mapping.UUID)
			lambdaKinesisMappingState(t, clients, source, id, "Disabled")
			put := func(payload string) *kinesis.PutRecordOutput {
				t.Helper()
				out, err := clients.kinesis("test", "test", "").PutRecord(t.Context(), &kinesis.PutRecordInput{StreamARN: &streamARN, PartitionKey: aws.String("window-key"), Data: []byte(payload)})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			setEnabled := func(enabled bool) {
				t.Helper()
				if _, err := lambdaDynamoDBClient(clients).UpdateEventSourceMapping(t.Context(), &awslambda.UpdateEventSourceMappingInput{UUID: &id, Enabled: &enabled}); err != nil {
					t.Fatal(err)
				}
				state := "Disabled"
				if enabled {
					state = "Enabled"
				}
				lambdaKinesisMappingState(t, clients, source, id, state)
			}
			first := put(`{"id":"first"}`)
			setEnabled(true)
			initial := lambdaKinesisInvocations(t, clients, source, fixture.Prefix, "KINESIS_WINDOW ", 1)[0].Event
			if len(initial["Records"].([]any)) != 1 || len(initial["state"].(map[string]any)) != 0 || initial["isFinalInvokeForWindow"] != false {
				t.Fatalf("first window invocation: %+v", initial)
			}
			deadline := time.Now().Add(90 * time.Second)
			committed := false
			for time.Now().Before(deadline) {
				advanceClock(t, source, 100*time.Millisecond)
				state, err := lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &id})
				if err != nil {
					t.Fatal(err)
				}
				if aws.ToString(state.LastProcessingResult) == "OK" {
					committed = true
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !committed {
				t.Fatal("window handler response was not committed")
			}
			setEnabled(false)
			clients = reopen()
			windowEnd, err := time.Parse(time.RFC3339Nano, initial["window"].(map[string]any)["end"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if delay := windowEnd.Add(2*time.Minute + time.Second).Sub(source.Now()); delay > 0 {
				advanceClock(t, source, delay)
			}
			setEnabled(true)
			final := lambdaKinesisInvocations(t, clients, source, fixture.Prefix, "KINESIS_WINDOW ", 2)[1].Event
			if len(final["Records"].([]any)) != 0 || final["isFinalInvokeForWindow"] != true || final["isWindowTerminatedEarly"] != false || final["state"].(map[string]any)["count"] != float64(1) || !reflect.DeepEqual(final["window"], initial["window"]) || final["shardId"] != aws.ToString(first.ShardId) {
				t.Fatalf("idle finalization lost retained window/state: %+v", final)
			}
			next := put(`{"id":"next"}`)
			invocations := lambdaKinesisInvocations(t, clients, source, fixture.Prefix, "KINESIS_WINDOW ", 3)
			if len(invocations) != 3 {
				t.Fatalf("idle window finalized more than once: %+v", invocations)
			}
			fresh := invocations[2].Event
			if len(fresh["Records"].([]any)) != 1 || len(fresh["state"].(map[string]any)) != 0 || fresh["isFinalInvokeForWindow"] != false || reflect.DeepEqual(fresh["window"], initial["window"]) {
				t.Fatalf("new window inherited finalized state: %+v", fresh)
			}
			record := fresh["Records"].([]any)[0].(map[string]any)
			if record["eventID"] != aws.ToString(next.ShardId)+":"+aws.ToString(next.SequenceNumber) {
				t.Fatalf("new window did not receive the newly accepted record: %+v", record)
			}
		})
	}
}
