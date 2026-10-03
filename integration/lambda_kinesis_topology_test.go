package stackd_test

import (
	"fmt"
	"testing"
	"time"

	"stackd/clock"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// All three shard generations are already in Kafka when polling starts. A merged
// child must wait for BOTH split parents; sibling invocation order is free.
func TestLambdaKinesisDockerRetainedTopology(t *testing.T) {
	lambdaURLDocker(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC))
			clients, reopen := lambdaKinesisCloud(t, backend, source)
			name := "lambda-kinesis-topology"
			k := clients.kinesis("test", "test", "")
			if _, err := k.CreateStream(t.Context(), &kinesis.CreateStreamInput{StreamName: &name, ShardCount: aws.Int32(1)}); err != nil {
				t.Fatal(err)
			}
			arn := awaitKinesisActive(t, source, k, name).StreamDescriptionSummary.StreamARN
			root := clients.iam("test", "test", "")
			role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: &name, AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			putRolePolicy(t, root, name, fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["kinesis:DescribeStream","kinesis:DescribeStreamSummary","kinesis:ListShards","kinesis:GetShardIterator","kinesis:GetRecords"],"Resource":%q},{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}`, aws.ToString(arn)))
			group := "/aws/lambda/" + name
			if _, err := logsClient(clients, "test").CreateLogGroup(t.Context(), &cloudwatchlogs.CreateLogGroupInput{LogGroupName: &group}); err != nil {
				t.Fatal(err)
			}
			// Keep siblings in the handler together so overlap is measured from
			// actual runtime intervals, not total test duration or log ordering.
			code := lambdaZIP(t, map[string]string{"handler.py": `import base64, json, time
def handler(event, context):
    started = time.time()
    label = json.loads(base64.b64decode(event['Records'][0]['kinesis']['data']))['id']
    if label in ('left', 'right'):
        time.sleep(5)
    response = {'finished': time.time()}
    marker = 'KINESIS_PROGRESS ' if label == 'checkpoint' else 'KINESIS_TOPOLOGY '
    print(marker + json.dumps({'request_id': context.aws_request_id, 'event': event, 'time': started, 'response': response}), flush=True)
    return response
`})
			if _, err := lambdaDynamoDBClient(clients).CreateFunction(t.Context(), &awslambda.CreateFunctionInput{FunctionName: &name, Role: role.Role.Arn, Runtime: lambdatypes.RuntimePython312, Handler: aws.String("handler.handler"), Code: &lambdatypes.FunctionCode{ZipFile: code}, Timeout: aws.Int32(60)}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionActiveWaiter(lambdaDynamoDBClient(clients), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			mapping, err := lambdaDynamoDBClient(clients).CreateEventSourceMapping(t.Context(), &awslambda.CreateEventSourceMappingInput{FunctionName: &name, EventSourceArn: arn, StartingPosition: lambdatypes.EventSourcePositionTrimHorizon, Enabled: aws.Bool(false), BatchSize: aws.Int32(1)})
			if err != nil {
				t.Fatal(err)
			}
			id := aws.ToString(mapping.UUID)
			lambdaKinesisMappingState(t, clients, source, id, "Disabled")
			written := map[string]*kinesis.PutRecordOutput{}
			put := func(label, hash string) {
				t.Helper()
				out, err := clients.kinesis("test", "test", "").PutRecord(t.Context(), &kinesis.PutRecordInput{StreamARN: arn, PartitionKey: aws.String(label), ExplicitHashKey: &hash, Data: []byte(fmt.Sprintf(`{"id":%q}`, label))})
				if err != nil {
					t.Fatal(err)
				}
				written[label] = out
			}
			put("parent", "0")
			if _, err := k.SplitShard(t.Context(), &kinesis.SplitShardInput{StreamARN: arn, ShardToSplit: written["parent"].ShardId, NewStartingHashKey: aws.String("170141183460469231731687303715884105728")}); err != nil {
				t.Fatal(err)
			}
			awaitKinesisActive(t, source, k, name)
			put("left", "0")
			put("right", "170141183460469231731687303715884105728")
			if _, err := k.MergeShards(t.Context(), &kinesis.MergeShardsInput{StreamARN: arn, ShardToMerge: written["left"].ShardId, AdjacentShardToMerge: written["right"].ShardId}); err != nil {
				t.Fatal(err)
			}
			awaitKinesisActive(t, source, k, name)
			put("merged", "0")
			put("checkpoint", "0")
			clients = reopen()
			lambdaKinesisMappingState(t, clients, source, id, "Disabled")
			if got := lambdaDynamoDBLogInvocations(t, clients, name, "KINESIS_TOPOLOGY "); len(got) != 0 {
				t.Fatalf("disabled mapping invoked retained history: %+v", got)
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
			setEnabled(true)
			lambdaKinesisInvocations(t, clients, source, name, "KINESIS_TOPOLOGY ", 4)
			// Observing a handler log does not acknowledge that same batch. A
			// later batch on the merged shard proves the preceding checkpoint
			// committed before disable/reopen. The in-flight marker may replay.
			lambdaKinesisInvocations(t, clients, source, name, "KINESIS_PROGRESS ", 1)
			setEnabled(false)
			put("resumed", "0")
			clients = reopen()
			lambdaKinesisMappingState(t, clients, source, id, "Disabled")
			if got := lambdaDynamoDBLogInvocations(t, clients, name, "KINESIS_TOPOLOGY "); len(got) != 4 {
				t.Fatalf("disabled resume changed delivered history: %+v", got)
			}
			setEnabled(true)
			got := lambdaKinesisInvocations(t, clients, source, name, "KINESIS_TOPOLOGY ", 5)
			positions := map[string]int{}
			for i, invocation := range got {
				records := invocation.Event["Records"].([]any)
				if len(records) != 1 {
					t.Fatalf("BatchSize=1 invocation: %+v", invocation.Event)
				}
				record := records[0].(map[string]any)
				label := lambdaKinesisRecordData(t, record)["id"].(string)
				if _, duplicate := positions[label]; duplicate {
					t.Fatalf("reopen replayed acknowledged record %s", label)
				}
				positions[label] = i
				out := written[label]
				if out == nil {
					t.Fatalf("unexpected runtime record %s", label)
				}
				data := record["kinesis"].(map[string]any)
				if record["eventSourceARN"] != aws.ToString(arn) || record["eventID"] != aws.ToString(out.ShardId)+":"+aws.ToString(out.SequenceNumber) || data["sequenceNumber"] != aws.ToString(out.SequenceNumber) || data["partitionKey"] != label {
					t.Fatalf("runtime envelope lost Kinesis identity: %+v", record)
				}
			}
			for _, label := range []string{"parent", "left", "right", "merged", "resumed"} {
				if _, ok := positions[label]; !ok {
					t.Fatalf("missing %s: %v", label, positions)
				}
			}
			if positions["parent"] >= positions["left"] || positions["parent"] >= positions["right"] || positions["left"] >= positions["merged"] || positions["right"] >= positions["merged"] || positions["merged"] >= positions["resumed"] {
				t.Fatalf("parent-before-child order violated: %v", positions)
			}
			left, right := got[positions["left"]], got[positions["right"]]
			if left.Time >= right.Response["finished"].(float64) || right.Time >= left.Response["finished"].(float64) {
				t.Fatalf("independent sibling shards did not overlap: left=[%v,%v] right=[%v,%v]", left.Time, left.Response["finished"], right.Time, right.Response["finished"])
			}
			parent, merged := got[positions["parent"]], got[positions["merged"]]
			if left.Time < parent.Response["finished"].(float64) || right.Time < parent.Response["finished"].(float64) || merged.Time < left.Response["finished"].(float64) || merged.Time < right.Response["finished"].(float64) {
				t.Fatal("child runtime started before both parent runtimes completed")
			}
		})
	}
}
