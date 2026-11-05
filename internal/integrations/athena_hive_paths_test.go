package integrations

import (
	"context"
	"reflect"
	"testing"

	native "stackd/engine/athena"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
	"stackd/internal/services/athena"
	"stackd/internal/services/glue"
)

func TestHiveRepairPreservesLiteralPathsAndNullSentinel(t *testing.T) {
	owner := glue.New(glue.Config{})
	defer owner.Close()
	caller := awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"}
	ctx := awsctx.WithMetadata(context.Background(), caller)
	const prefix = "literal%2Froot space/雪/"
	source := &hiveDiscoveryFixture{keys: []string{prefix + "day=us%2Feast/data", prefix + "day=space value/data", prefix + "day=雪/data", prefix + "day=__HIVE_DEFAULT_PARTITION__/data"}}
	engine := AthenaEngine{Glue: owner, S3: source}
	catalog := AthenaGlue{Glue: owner}
	request := athena.ExecutionRequest{Query: athena.QueryRecord{Key: athena.ResourceKey{Scope: athena.Scope{Partition: caller.Partition, AccountID: caller.AccountID, Region: caller.Region}, Name: "literal-repair"}, Caller: caller}}
	for _, plan := range []native.HiveDDL{{Kind: "CREATE_DATABASE", Identifier: []string{"fixture"}}, {Kind: "CREATE_TABLE", Identifier: []string{"fixture", "literal"}, External: true, Location: "s3://fixture-data/" + prefix, Columns: []native.DDLColumn{{Name: "id", Type: "bigint"}, {Name: "day", Type: "string"}}, PartitionColumns: []string{"day"}}} {
		if err := engine.applyHiveDDL(ctx, request, plan); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := engine.applyHiveDDL(ctx, request, native.HiveDDL{Kind: "MSCK_REPAIR", Identifier: []string{"fixture", "literal"}}); err != nil {
			t.Fatal(err)
		}
	}
	if source.prefix != prefix {
		t.Fatalf("listing decoded root: %q want %q", source.prefix, prefix)
	}
	raw, rejected := catalog.command(ctx, "GetPartitions", &api.GetPartitionsInput{DatabaseName: new(api.NameString("fixture")), TableName: new(api.NameString("literal"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	partitions := raw.(*api.GetPartitionsOutput).Partitions
	if len(partitions) != 4 {
		t.Fatalf("repair was not idempotent: %+v", partitions)
	}
	expected := map[string]string{"us/east": "day=us%2Feast/", "space value": "day=space value/", "雪": "day=雪/", "__HIVE_DEFAULT_PARTITION__": "day=__HIVE_DEFAULT_PARTITION__/"}
	for _, partition := range partitions {
		value := string(partition.Values[0])
		suffix, ok := expected[value]
		if !ok {
			t.Fatalf("unexpected partition value %q", value)
		}
		if got := hiveValue(partition.StorageDescriptor.Location); got != "s3://fixture-data/"+prefix+suffix {
			t.Fatalf("literal location changed: %q", got)
		}
	}
}

func TestHivePartitionSpecCaseAndDuplicateValidation(t *testing.T) {
	keys := api.ColumnList{{Name: new(api.NameString("day"))}, {Name: new(api.NameString("region"))}}
	values, err := hivePartitionValues(keys, map[string]string{"DAY": "today", "ReGiOn": "west"})
	if err != nil || !reflect.DeepEqual(values, api.ValueStringList{"today", "west"}) {
		t.Fatalf("case-insensitive spec: %v %v", values, err)
	}
	for _, spec := range []map[string]string{{"DAY": "a", "day": "b"}, {"DAY": "a", "day": "b", "region": "west"}, {"DAY": "a", "unknown": "west"}} {
		if _, err := hivePartitionValues(keys, spec); err == nil {
			t.Fatalf("invalid/duplicate partition spec accepted: %v", spec)
		}
	}
}
