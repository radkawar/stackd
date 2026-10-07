package integrations

import (
	"errors"
	"strings"
	"testing"

	ddbapi "stackd/internal/awsapi/dynamodb"
	kinesisapi "stackd/internal/awsapi/kinesis"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/dynamodb"
	"stackd/internal/services/kinesis"
)

// cfnGuardJobsTable is the jobs table shape from the Guard local template:
// on-demand username/key keys, sixteen GSIs, TTL and a NEW_AND_OLD_IMAGES stream.
func cfnGuardJobsTable() cloudformation.Properties {
	attributes := []any{
		map[string]any{"AttributeName": "username", "AttributeType": "S"},
		map[string]any{"AttributeName": "key", "AttributeType": "S"},
		map[string]any{"AttributeName": "_tenant", "AttributeType": "S"},
	}
	var indexes []any
	for _, name := range []string{"Name", "Status", "Source", "Stats", "Created", "Updated", "Delayed", "Conversation", "Hunt", "Location", "Email", "Registrar", "Logit", "Parent_Id", "BandIndex"} {
		attribute := strings.ToLower(name)
		attributes = append(attributes, map[string]any{"AttributeName": attribute, "AttributeType": "S"})
		projection := map[string]any{"ProjectionType": "ALL"}
		switch name {
		case "Stats":
			projection = map[string]any{"ProjectionType": "INCLUDE", "NonKeyAttributes": []any{"status", "started", "finished", "source"}}
		case "BandIndex":
			projection = map[string]any{"ProjectionType": "INCLUDE", "NonKeyAttributes": []any{"cache_key", "similarity_hash", "ttl"}}
		}
		indexes = append(indexes, map[string]any{"IndexName": name, "Projection": projection, "KeySchema": []any{
			map[string]any{"AttributeName": "username", "KeyType": "HASH"},
			map[string]any{"AttributeName": attribute, "KeyType": "RANGE"},
		}})
	}
	indexes = append(indexes, map[string]any{"IndexName": "_tenant", "Projection": map[string]any{"ProjectionType": "KEYS_ONLY"}, "KeySchema": []any{
		map[string]any{"AttributeName": "_tenant", "KeyType": "HASH"},
		map[string]any{"AttributeName": "key", "KeyType": "RANGE"},
	}})
	return cloudformation.Properties{
		"TableName":               "local",
		"BillingMode":             "PAY_PER_REQUEST",
		"AttributeDefinitions":    attributes,
		"KeySchema":               []any{map[string]any{"AttributeName": "username", "KeyType": "HASH"}, map[string]any{"AttributeName": "key", "KeyType": "RANGE"}},
		"GlobalSecondaryIndexes":  indexes,
		"TimeToLiveSpecification": map[string]any{"AttributeName": "ttl", "Enabled": true},
		"StreamSpecification":     map[string]any{"StreamViewType": "NEW_AND_OLD_IMAGES"},
		"SSESpecification":        map[string]any{"SSEEnabled": "false"},
	}
}

func cfnDataTestContext() (awsctx.Metadata, cloudformation.Scope) {
	return awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-2", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"},
		cloudformation.Scope{Partition: "aws", Account: "000000000000", Region: "us-east-2"}
}

func cfnDataTestRequest(scope cloudformation.Scope, kind, logical string, p cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{StackID: "arn:aws:cloudformation:us-east-2:000000000000:stack/guard/id", StackName: "guard", LogicalID: logical, Type: kind, Token: logical + "-incarnation", Scope: scope, Properties: p}
}

func TestDataStreamGuardPropertiesAdmission(t *testing.T) {
	table := cfnGuardJobsTable()
	p, err := cfnDDBTableDecode(table)
	if err != nil {
		t.Fatal(err)
	}
	in, err := cfnDDBCreateInput(p, "local", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(in["GlobalSecondaryIndexes"].([]map[string]any)); got != 16 {
		t.Fatalf("CreateTable lost Guard indexes: %d", got)
	}
	if _, ok := in["TimeToLiveSpecification"]; ok {
		t.Fatal("TTL must be applied by UpdateTimeToLive after ACTIVE, not CreateTable")
	}
	if stream := in["StreamSpecification"].(map[string]any); stream["StreamEnabled"] != true || stream["StreamViewType"] != "NEW_AND_OLD_IMAGES" {
		t.Fatalf("stream specification was not enabled: %+v", stream)
	}

	encrypted := cfnGuardJobsTable()
	encrypted["SSESpecification"] = map[string]any{"SSEEnabled": true}
	if err := (cfnDynamoDBTable{}).Validate(encrypted); err == nil || !strings.Contains(err.Error(), "SSESpecification") {
		t.Fatalf("KMS encryption was silently accepted: %v", err)
	}

	stream := cfnKinesisStream{}
	if err := stream.Validate(cloudformation.Properties{"Name": "results", "RetentionPeriodHours": "720", "StreamModeDetails": map[string]any{"StreamMode": "ON_DEMAND"}}); err != nil {
		t.Fatalf("ON_DEMAND stream without ShardCount rejected: %v", err)
	}
	for name, p := range map[string]cloudformation.Properties{
		"provisioned without shards": {"Name": "results"},
		"auto distribution":          {"StreamModeDetails": map[string]any{"StreamMode": "ON_DEMAND"}, "RecordDistributionStrategy": "AUTO"},
		"on-demand shard count":      {"StreamModeDetails": map[string]any{"StreamMode": "ON_DEMAND"}, "ShardCount": 2},
	} {
		if err := stream.Validate(p); err == nil {
			t.Errorf("%s was admitted", name)
		}
	}
}

func TestDataStreamReplacementSemantics(t *testing.T) {
	h := cfnDynamoDBTable{}
	base := cfnGuardJobsTable()
	delete(base, "TableName")
	for name, change := range map[string]struct {
		mutate  func(cloudformation.Properties)
		replace bool
	}{
		"ttl change updates in place": {func(p cloudformation.Properties) { p["TimeToLiveSpecification"] = map[string]any{"Enabled": false} }, false},
		"new attribute updates in place": {func(p cloudformation.Properties) {
			p["AttributeDefinitions"] = append(p["AttributeDefinitions"].([]any), map[string]any{"AttributeName": "extra", "AttributeType": "N"})
		}, false},
		"attribute type change replaces": {func(p cloudformation.Properties) {
			p["AttributeDefinitions"].([]any)[1] = map[string]any{"AttributeName": "key", "AttributeType": "N"}
		}, true},
		"key schema change replaces": {func(p cloudformation.Properties) {
			p["KeySchema"] = []any{map[string]any{"AttributeName": "username", "KeyType": "HASH"}}
		}, true},
		"generated name change replaces": {func(p cloudformation.Properties) { p["TableName"] = "renamed" }, true},
	} {
		t.Run(name, func(t *testing.T) {
			after := cfnGuardJobsTable()
			delete(after, "TableName")
			after["AttributeDefinitions"] = append([]any(nil), after["AttributeDefinitions"].([]any)...)
			change.mutate(after)
			got, err := h.Replacement(base, after)
			if err != nil || got != change.replace {
				t.Fatalf("replacement = %v, %v; want %v", got, err, change.replace)
			}
		})
	}
	named := cfnGuardJobsTable()
	keyed := cfnGuardJobsTable()
	keyed["KeySchema"] = []any{map[string]any{"AttributeName": "username", "KeyType": "HASH"}}
	if _, err := h.Replacement(named, keyed); err == nil {
		t.Fatal("custom-named table replacement would collide with its own name")
	}
	// Renaming an index is one delete plus one create; CloudFormation rejects it.
	before, _ := cfnDDBTableDecode(cfnGuardJobsTable())
	renamed := cfnGuardJobsTable()
	renamed["GlobalSecondaryIndexes"].([]any)[0].(map[string]any)["IndexName"] = "Renamed"
	after, _ := cfnDDBTableDecode(renamed)
	if n := cfnDDBIndexChanges(before.GlobalSecondaryIndexes, after.GlobalSecondaryIndexes); n != 2 {
		t.Fatalf("index rename counted as %d structural changes", n)
	}
}

func TestDataStreamOnDemandRemovalUsesOwnerSentinel(t *testing.T) {
	read := ddbapi.LongObject(10)
	update := cfnDDBOnDemandUpdate(nil, &ddbapi.OnDemandThroughput{MaxReadRequestUnits: &read})
	if update["MaxReadRequestUnits"] != int64(-1) || len(update) != 1 {
		t.Fatalf("removed on-demand maximum was not cleared: %+v", update)
	}
	unset := ddbapi.LongObject(-1)
	if update := cfnDDBOnDemandUpdate(nil, &ddbapi.OnDemandThroughput{MaxReadRequestUnits: &unset, MaxWriteRequestUnits: &unset}); update != nil {
		t.Fatalf("unchanged unlimited throughput produced an update: %+v", update)
	}
}

func cfnDataRequireCode(t *testing.T, err error, code string) {
	t.Helper()
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

// Without an engine the owner must reject before admitting a table that could
// never leave CREATING; the Guard schema itself passes owner validation first.
func TestDataStreamCreateWithoutEnginesAdmitsNothing(t *testing.T) {
	metadata, scope := cfnDataTestContext()
	ctx := awsctx.WithMetadata(t.Context(), metadata)
	tables := dynamodb.New(dynamodb.Config{})
	streams := kinesis.New(kinesis.Config{})
	t.Cleanup(func() { _ = tables.Close(); _ = streams.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"dynamodb": tables, "kinesis": streams})
	handlers := CloudFormationDataStreamHandlers(commands)

	table := cfnDataTestRequest(scope, "AWS::DynamoDB::Table", "Jobs", cfnGuardJobsTable())
	_, err := handlers[table.Type].Create(ctx, table)
	cfnDataRequireCode(t, err, "ServiceUnavailable")
	_, err = cfnComputeCall[ddbapi.DescribeTableOutput](ctx, commands, "dynamodb", "DescribeTable", map[string]any{"TableName": "local"})
	cfnDataRequireCode(t, err, "ResourceNotFoundException")

	stream := cfnDataTestRequest(scope, "AWS::Kinesis::Stream", "Results", cloudformation.Properties{"Name": "results", "RetentionPeriodHours": 720, "StreamModeDetails": map[string]any{"StreamMode": "ON_DEMAND"}})
	_, err = handlers[stream.Type].Create(ctx, stream)
	cfnDataRequireCode(t, err, "ServiceUnavailable")
	listed, err := cfnComputeCall[kinesisapi.ListStreamsOutput](ctx, commands, "kinesis", "ListStreams", map[string]any{})
	if err != nil || len(listed.StreamNames) != 0 || len(listed.StreamSummaries) != 0 {
		t.Fatalf("stream admitted without a record runtime: %+v %v", listed, err)
	}
	// Rollback deletion of the never-created resources is a no-op.
	for _, r := range []cloudformation.ResourceRequest{table, stream} {
		r.PhysicalID = cfnComputeString(r.Properties, map[string]string{"AWS::DynamoDB::Table": "TableName", "AWS::Kinesis::Stream": "Name"}[r.Type])
		if err := handlers[r.Type].Delete(ctx, r); err != nil {
			t.Fatalf("delete %s: %v", r.Type, err)
		}
	}
}
