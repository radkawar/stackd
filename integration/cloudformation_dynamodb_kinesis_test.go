package stackd_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	"stackd"
	"stackd/clock"
	dynamoengine "stackd/engine/dynamodb"
)

// cloudFormationGuardDataTemplate is the Guard jobs table and results stream:
// on-demand username/key keys, sixteen GSIs, TTL, NEW_AND_OLD_IMAGES and an
// ON_DEMAND Kinesis stream without ShardCount retaining 720 hours.
func cloudFormationGuardDataTemplate(t *testing.T) string {
	t.Helper()
	attributes := []map[string]string{{"AttributeName": "username", "AttributeType": "S"}, {"AttributeName": "key", "AttributeType": "S"}, {"AttributeName": "_tenant", "AttributeType": "S"}}
	var indexes []any
	for _, name := range []string{"Name", "Status", "Source", "Stats", "Created", "Updated", "Delayed", "Conversation", "Hunt", "Location", "Email", "Registrar", "Logit", "Parent_Id", "BandIndex"} {
		attribute := strings.ToLower(name)
		attributes = append(attributes, map[string]string{"AttributeName": attribute, "AttributeType": "S"})
		projection := map[string]any{"ProjectionType": "ALL"}
		switch name {
		case "Stats":
			projection = map[string]any{"ProjectionType": "INCLUDE", "NonKeyAttributes": []string{"status", "started", "finished", "source"}}
		case "BandIndex":
			projection = map[string]any{"ProjectionType": "INCLUDE", "NonKeyAttributes": []string{"cache_key", "similarity_hash", "ttl"}}
		}
		indexes = append(indexes, map[string]any{"IndexName": name, "Projection": projection, "KeySchema": []map[string]string{{"AttributeName": "username", "KeyType": "HASH"}, {"AttributeName": attribute, "KeyType": "RANGE"}}})
	}
	indexes = append(indexes, map[string]any{"IndexName": "_tenant", "Projection": map[string]string{"ProjectionType": "KEYS_ONLY"}, "KeySchema": []map[string]string{{"AttributeName": "_tenant", "KeyType": "HASH"}, {"AttributeName": "key", "KeyType": "RANGE"}}})
	body, err := json.Marshal(map[string]any{
		"Resources": map[string]any{
			"Jobs": map[string]any{"Type": "AWS::DynamoDB::Table", "Properties": map[string]any{
				"TableName": "local", "BillingMode": "PAY_PER_REQUEST", "AttributeDefinitions": attributes,
				"KeySchema":               []map[string]string{{"AttributeName": "username", "KeyType": "HASH"}, {"AttributeName": "key", "KeyType": "RANGE"}},
				"GlobalSecondaryIndexes":  indexes,
				"TimeToLiveSpecification": map[string]any{"AttributeName": "ttl", "Enabled": true},
				"StreamSpecification":     map[string]string{"StreamViewType": "NEW_AND_OLD_IMAGES"},
			}},
			"Results": map[string]any{"Type": "AWS::Kinesis::Stream", "Properties": map[string]any{
				"Name": "results", "RetentionPeriodHours": 720, "StreamModeDetails": map[string]string{"StreamMode": "ON_DEMAND"},
			}},
		},
		"Outputs": map[string]any{
			"TableArn":   map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Jobs", "Arn"}}},
			"StreamArn":  map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Jobs", "StreamArn"}}},
			"ResultsArn": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Results", "Arn"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func awaitCloudFormationDataStack(t *testing.T, clients cloudClients, source *clock.Manual, stackID string, wanted cfntypes.StackStatus) cfntypes.Stack {
	t.Helper()
	client := cloudFormationClient(clients, "us-east-1", "test", "test")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	for ctx.Err() == nil {
		if _, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000); err != nil {
			t.Fatal(err)
		}
		out, err := client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: aws.String(stackID)})
		if err != nil {
			t.Fatal(err)
		}
		stack := out.Stacks[0]
		if stack.StackStatus == wanted {
			return stack
		}
		if !cloudFormationTransient(map[string]any{"Stacks": []any{map[string]any{"StackStatus": string(stack.StackStatus)}}}) {
			events, _ := client.DescribeStackEvents(ctx, &cloudformation.DescribeStackEventsInput{StackName: aws.String(stackID)})
			t.Fatalf("wanted %s, got %s: %s %+v", wanted, stack.StackStatus, aws.ToString(stack.StackStatusReason), events)
		}
		advanceClock(t, source, time.Second)
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("stack did not reach %s: %v", wanted, ctx.Err())
	return cfntypes.Stack{}
}

// Without configured engines the owners reject admission; the stack rolls back
// without retaining a table that could never become ACTIVE.
func TestCloudFormationDataStreamsWithoutEngines(t *testing.T) {
	source := clock.NewManual(time.Date(2031, 4, 5, 6, 7, 8, 0, time.UTC))
	clients := clockCloud(t, stackd.Config{Clock: source})
	cfn := cloudFormationClient(clients, "us-east-1", "test", "test")
	created, err := cfn.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("guard-data"), TemplateBody: aws.String(cloudFormationGuardDataTemplate(t))})
	if err != nil {
		t.Fatal(err)
	}
	stackID := aws.ToString(created.StackId)
	awaitCloudFormationDataStack(t, clients, source, stackID, cfntypes.StackStatusRollbackComplete)
	events, err := cfn.DescribeStackEvents(t.Context(), &cloudformation.DescribeStackEventsInput{StackName: aws.String(stackID)})
	if err != nil {
		t.Fatal(err)
	}
	unavailable := false
	for _, event := range events.StackEvents {
		if event.ResourceStatus == cfntypes.ResourceStatusCreateFailed && strings.Contains(aws.ToString(event.ResourceStatusReason), "runtime is not configured") {
			unavailable = true
		}
	}
	if !unavailable {
		t.Fatalf("missing-engine failure was not reported: %+v", events.StackEvents)
	}
	tables, err := dynamoClient(clients, "test", "test", clients.server.Client()).ListTables(t.Context(), &dynamodb.ListTablesInput{})
	if err != nil || len(tables.TableNames) != 0 {
		t.Fatalf("table retained without an engine: %+v %v", tables, err)
	}
	streams, err := clients.kinesis("test", "test", "").ListStreams(t.Context(), &kinesis.ListStreamsInput{})
	if err != nil || len(streams.StreamNames) != 0 {
		t.Fatalf("stream retained without a runtime: %+v %v", streams, err)
	}
}

// CloudFormation drives the real owners and waits for native ACTIVE before
// completing; the data planes then serve item, GSI and record traffic.
func TestCloudFormationGuardDataPlane(t *testing.T) {
	if os.Getenv("STACKD_DYNAMODB_DOCKER") != "1" {
		t.Skip("set STACKD_DYNAMODB_DOCKER=1 and STACKD_KINESIS_DOCKER=1 to exercise pinned DynamoDB Local and Kafka")
	}
	logs := newKinesisReplayRuntime(t)
	runtime, err := dynamoengine.NewDocker(t.Context(), dynamoengine.DockerConfig{Client: logs.client})
	if err != nil {
		t.Fatal(err)
	}
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
	source := clock.NewManual(time.Date(2031, 4, 5, 6, 7, 8, 0, time.UTC))
	clients, _ := retainedCloud(t, "memory", stackd.Config{Clock: source, DynamoDBRuntime: owned, KinesisRuntime: logs})
	cfn := cloudFormationClient(clients, "us-east-1", "test", "test")
	created, err := cfn.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("guard-data"), TemplateBody: aws.String(cloudFormationGuardDataTemplate(t))})
	if err != nil {
		t.Fatal(err)
	}
	stackID := aws.ToString(created.StackId)
	stack := awaitCloudFormationDataStack(t, clients, source, stackID, cfntypes.StackStatusCreateComplete)
	outputs := map[string]string{}
	for _, output := range stack.Outputs {
		outputs[aws.ToString(output.OutputKey)] = aws.ToString(output.OutputValue)
	}

	ddb := dynamoClient(clients, "test", "test", clients.server.Client())
	table, err := ddb.DescribeTable(t.Context(), &dynamodb.DescribeTableInput{TableName: aws.String("local")})
	if err != nil {
		t.Fatal(err)
	}
	if table.Table.TableStatus != dynamodbtypes.TableStatusActive || len(table.Table.GlobalSecondaryIndexes) != 16 || aws.ToString(table.Table.LatestStreamArn) != outputs["StreamArn"] || aws.ToString(table.Table.TableArn) != outputs["TableArn"] {
		t.Fatalf("stack completed before the owned table was ready: %+v outputs=%v", table.Table, outputs)
	}
	ttl, err := ddb.DescribeTimeToLive(t.Context(), &dynamodb.DescribeTimeToLiveInput{TableName: aws.String("local")})
	if err != nil || ttl.TimeToLiveDescription.TimeToLiveStatus != dynamodbtypes.TimeToLiveStatusEnabled || aws.ToString(ttl.TimeToLiveDescription.AttributeName) != "ttl" {
		t.Fatalf("TTL was not applied: %+v %v", ttl, err)
	}
	item := map[string]dynamodbtypes.AttributeValue{
		"username": &dynamodbtypes.AttributeValueMemberS{Value: "user@example.com"},
		"key":      &dynamodbtypes.AttributeValueMemberS{Value: "#job#1"},
		"status":   &dynamodbtypes.AttributeValueMemberS{Value: "JQ"},
	}
	if _, err := ddb.PutItem(t.Context(), &dynamodb.PutItemInput{TableName: aws.String("local"), Item: item}); err != nil {
		t.Fatal(err)
	}
	got, err := ddb.GetItem(t.Context(), &dynamodb.GetItemInput{TableName: aws.String("local"), Key: map[string]dynamodbtypes.AttributeValue{"username": item["username"], "key": item["key"]}})
	if err != nil || len(got.Item) != 3 {
		t.Fatalf("item was not served: %+v %v", got, err)
	}
	query, err := ddb.Query(t.Context(), &dynamodb.QueryInput{TableName: aws.String("local"), IndexName: aws.String("Status"),
		KeyConditionExpression:    aws.String("username = :u AND #s = :s"),
		ExpressionAttributeNames:  map[string]string{"#s": "status"},
		ExpressionAttributeValues: map[string]dynamodbtypes.AttributeValue{":u": item["username"], ":s": item["status"]}})
	if err != nil || query.Count != 1 {
		t.Fatalf("Status GSI query failed: %+v %v", query, err)
	}

	kin := clients.kinesis("test", "test", "")
	summary, err := kin.DescribeStreamSummary(t.Context(), &kinesis.DescribeStreamSummaryInput{StreamName: aws.String("results")})
	if err != nil {
		t.Fatal(err)
	}
	if s := summary.StreamDescriptionSummary; s.StreamStatus != kinesistypes.StreamStatusActive || s.StreamModeDetails.StreamMode != kinesistypes.StreamModeOnDemand || aws.ToInt32(s.RetentionPeriodHours) != 720 || aws.ToString(s.StreamARN) != outputs["ResultsArn"] {
		t.Fatalf("stream did not converge before completion: %+v", s)
	}
	if _, err := kin.PutRecord(t.Context(), &kinesis.PutRecordInput{StreamName: aws.String("results"), PartitionKey: aws.String("job"), Data: []byte(`{"route":"results"}`)}); err != nil {
		t.Fatal(err)
	}
	shards, err := kin.ListShards(t.Context(), &kinesis.ListShardsInput{StreamName: aws.String("results")})
	if err != nil {
		t.Fatal(err)
	}
	iterators := map[string]*string{}
	for _, shard := range shards.Shards {
		iterator, err := kin.GetShardIterator(t.Context(), &kinesis.GetShardIteratorInput{StreamName: aws.String("results"), ShardId: shard.ShardId, ShardIteratorType: kinesistypes.ShardIteratorTypeTrimHorizon})
		if err != nil {
			t.Fatal(err)
		}
		iterators[aws.ToString(shard.ShardId)] = iterator.ShardIterator
	}
	found := false
	for attempt := 0; attempt < 100 && !found; attempt++ {
		for shard, iterator := range iterators {
			page, err := kin.GetRecords(t.Context(), &kinesis.GetRecordsInput{ShardIterator: iterator})
			if err != nil {
				t.Fatal(err)
			}
			iterators[shard] = page.NextShardIterator
			for _, record := range page.Records {
				found = found || string(record.Data) == `{"route":"results"}`
			}
		}
		advanceClock(t, source, 200*time.Millisecond)
		time.Sleep(100 * time.Millisecond)
	}
	if !found {
		t.Fatal("record was not readable from the stream")
	}

	if _, err := cfn.DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(stackID)}); err != nil {
		t.Fatal(err)
	}
	awaitCloudFormationDataStack(t, clients, source, stackID, cfntypes.StackStatusDeleteComplete)
	_, err = ddb.DescribeTable(t.Context(), &dynamodb.DescribeTableInput{TableName: aws.String("local")})
	assertAPIError(t, err, "ResourceNotFoundException")
	_, err = kin.DescribeStreamSummary(t.Context(), &kinesis.DescribeStreamSummaryInput{StreamName: aws.String("results")})
	assertAPIError(t, err, "ResourceNotFoundException")
}
