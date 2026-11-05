package integrations

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	native "stackd/engine/athena"
	api "stackd/internal/awsapi/glue"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/athena"
	"stackd/internal/services/glue"
)

type hiveDiscoveryFixture struct {
	keys   []string
	denied bool
	caller awsctx.Metadata
	prefix string
}

func (s *hiveDiscoveryFixture) ServeHTTP(http.ResponseWriter, *http.Request) {
	panic("discovery fixture is not an HTTP data engine")
}
func (s *hiveDiscoveryFixture) ListObjectsV2(ctx context.Context, input *s3api.ListObjectsV2Input) (*s3api.ListObjectsV2Output, *awswire.Error) {
	s.caller = awsctx.FromContext(ctx)
	s.prefix = hiveValue(input.Prefix)
	if s.denied {
		return nil, &awswire.Error{Code: "AccessDenied", Message: "fixture current source deny", StatusCode: 403}
	}
	out := &s3api.ListObjectsV2Output{}
	for _, key := range s.keys {
		out.Contents = append(out.Contents, s3api.Object{Key: new(s3api.ObjectKey(key))})
	}
	return out, nil
}

func TestHiveTypedMetadataPartitionLifecycleAndCurrentAuthority(t *testing.T) {
	owner := glue.New(glue.Config{})
	defer owner.Close()
	metadata := awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"}
	ctx := awsctx.WithMetadata(context.Background(), metadata)
	source := &hiveDiscoveryFixture{}
	engine := AthenaEngine{Glue: owner, S3: source}
	catalog := AthenaGlue{Glue: owner}
	request := athena.ExecutionRequest{Query: athena.QueryRecord{Key: athena.ResourceKey{Scope: athena.Scope{Partition: metadata.Partition, AccountID: metadata.AccountID, Region: metadata.Region}, Name: "hive-regression"}, Caller: metadata}}
	call := func(action string, input any) any {
		t.Helper()
		out, err := catalog.command(ctx, action, input)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return out
	}
	apply := func(plan native.HiveDDL) {
		t.Helper()
		if len(plan.Identifier) == 0 {
			plan.Identifier = []string{"fixture", "events"}
		}
		if err := engine.applyHiveDDL(ctx, request, plan); err != nil {
			t.Fatalf("%s: %v", plan.Kind, err)
		}
	}
	table := func() *api.Table {
		t.Helper()
		return call("GetTable", &api.GetTableInput{DatabaseName: new(api.NameString("fixture")), Name: new(api.NameString("events"))}).(*api.GetTableOutput).Table
	}
	partition := func(value string) *api.Partition {
		t.Helper()
		return call("GetPartition", &api.GetPartitionInput{DatabaseName: new(api.NameString("fixture")), TableName: new(api.NameString("events")), PartitionValues: api.ValueStringList{api.ValueString(value)}}).(*api.GetPartitionOutput).Partition
	}
	apply(native.HiveDDL{Kind: "CREATE_DATABASE", Identifier: []string{"fixture"}})
	apply(native.HiveDDL{Kind: "CREATE_TABLE", External: true, Location: "s3://fixture-data/events/", Columns: []native.DDLColumn{{Name: "id", Type: "bigint"}, {Name: "day", Type: "string"}}, PartitionColumns: []string{"day"}, BucketColumns: []string{"id"}, BucketCount: 4, Serde: "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe", InputFormat: "org.apache.hadoop.mapred.TextInputFormat", OutputFormat: "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"})
	if got := table(); got.StorageDescriptor.NumberOfBuckets == nil || *got.StorageDescriptor.NumberOfBuckets != 4 || !reflect.DeepEqual(got.StorageDescriptor.BucketColumns, api.NameStringList{"id"}) {
		t.Fatalf("bucket metadata not retained: %+v", got.StorageDescriptor)
	}
	apply(native.HiveDDL{Kind: "SET_DATABASE_PROPERTIES", Identifier: []string{"fixture"}, Properties: map[string]string{"purpose": "regression"}})
	apply(native.HiveDDL{Kind: "SET_TABLE_PROPERTIES", Properties: map[string]string{"owner": "fixture"}})
	apply(native.HiveDDL{Kind: "ADD_COLUMNS", Columns: []native.DDLColumn{{Name: "value", Type: "string"}}})
	apply(native.HiveDDL{Kind: "CHANGE_COLUMN", OldColumn: "value", First: true, Columns: []native.DDLColumn{{Name: "payload", Type: "string", Comment: "renamed"}}})
	if got := table(); hiveValue(got.StorageDescriptor.Columns[0].Name) != "payload" || string(got.Parameters["owner"]) != "fixture" {
		t.Fatalf("metadata update lost retained fields: %+v", got)
	}
	apply(native.HiveDDL{Kind: "ADD_PARTITIONS", Partitions: []native.DDLPartition{{Values: map[string]string{"day": "a/b"}}}})
	if got := hiveValue(partition("a/b").StorageDescriptor.Location); got != "s3://fixture-data/events/day=a%2Fb/" {
		t.Fatalf("Hive escaping = %q", got)
	}
	apply(native.HiveDDL{Kind: "SET_LOCATION", Location: "s3://fixture-data/moved/", Partitions: []native.DDLPartition{{Values: map[string]string{"day": "a/b"}}}})
	apply(native.HiveDDL{Kind: "RENAME_PARTITION", Partitions: []native.DDLPartition{{Values: map[string]string{"day": "a/b"}}}, NewPartition: map[string]string{"day": "renamed"}})
	if got := hiveValue(partition("renamed").StorageDescriptor.Location); got != "s3://fixture-data/moved/" {
		t.Fatalf("rename moved partition data: %q", got)
	}
	apply(native.HiveDDL{Kind: "REPLACE_COLUMNS", Partitions: []native.DDLPartition{{Values: map[string]string{"day": "renamed"}}}, Columns: []native.DDLColumn{{Name: "local", Type: "bigint"}}})
	if hiveValue(partition("renamed").StorageDescriptor.Columns[0].Name) != "local" || hiveValue(table().StorageDescriptor.Columns[0].Name) != "payload" {
		t.Fatal("partition-only REPLACE changed table schema")
	}
	source.keys = []string{"events/day=discovered/data", "events/day=bad%3Atime/data", "events/Day=upper/data", "events/sub/day=nested/data"}
	source.denied = true
	if err := engine.applyHiveDDL(ctx, request, native.HiveDDL{Kind: "MSCK_REPAIR", Identifier: []string{"fixture", "events"}}); err == nil {
		t.Fatal("MSCK bypassed current source access")
	}
	source.denied = false
	apply(native.HiveDDL{Kind: "MSCK_REPAIR"})
	apply(native.HiveDDL{Kind: "MSCK_REPAIR"})
	partition("discovered")
	partition("nested")
	partition("renamed")
	if source.caller.PrincipalARN != metadata.PrincipalARN || source.caller.InvokedBy != "athena.amazonaws.com" {
		t.Fatalf("MSCK lost current caller: %+v", source.caller)
	}
	source.keys = nil
	apply(native.HiveDDL{Kind: "MSCK_REPAIR"})
	partition("discovered")
	apply(native.HiveDDL{Kind: "DROP_PARTITIONS", Partitions: []native.DDLPartition{{Values: map[string]string{"day": "renamed"}}}})
	apply(native.HiveDDL{Kind: "DROP_PARTITIONS", IfExists: true, Partitions: []native.DDLPartition{{Values: map[string]string{"day": "renamed"}}}})
	for _, plan := range []native.HiveDDL{{Kind: "ADD_COLUMNS", Columns: []native.DDLColumn{{Name: "id", Type: "int"}}}, {Kind: "CHANGE_COLUMN", OldColumn: "missing", Columns: []native.DDLColumn{{Name: "x", Type: "int"}}}, {Kind: "SET_LOCATION", Location: "s3a://fixture-data/wrong/"}, {Kind: "ADD_PARTITIONS", Partitions: []native.DDLPartition{{Values: map[string]string{"unknown": "value"}}}}} {
		plan.Identifier = []string{"fixture", "events"}
		if err := engine.applyHiveDDL(ctx, request, plan); err == nil {
			t.Fatalf("invalid %s accepted", plan.Kind)
		}
	}
	call("PutResourcePolicy", &api.PutResourcePolicyInput{PolicyInJson: new(api.PolicyJsonString(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"glue:UpdateTable","Resource":"*"}]}`))})
	if err := engine.applyHiveDDL(ctx, request, native.HiveDDL{Kind: "SET_TABLE_PROPERTIES", Identifier: []string{"fixture", "events"}, Properties: map[string]string{"owner": "denied"}}); err == nil {
		t.Fatal("ALTER bypassed current Glue policy")
	}
	if string(table().Parameters["owner"]) != "fixture" {
		t.Fatal("denied ALTER changed retained metadata")
	}
}

func TestHiveDiscoveryAndEscaping(t *testing.T) {
	keys := api.ColumnList{{Name: new(api.NameString("day"))}, {Name: new(api.NameString("region"))}}
	for _, item := range []struct {
		key    string
		valid  bool
		values api.ValueStringList
	}{
		{"root/day=2026-01-01/region=us%2Feast/data", true, api.ValueStringList{"2026-01-01", "us/east"}},
		{"root/deep/day=2026/region=west/", true, api.ValueStringList{"2026", "west"}},
		{"root/day=bad%3Avalue/region=west/data", false, nil},
		{"root/Day=2026/region=west/data", false, nil},
		{"other/day=2026/region=west/data", false, nil},
		{"root/day=2026/region=west", false, nil},
	} {
		values, _, ok := discoverHivePartition("root/", item.key, keys)
		if ok != item.valid || !reflect.DeepEqual(values, item.values) {
			t.Errorf("%q => %v %v", item.key, values, ok)
		}
	}
	if got := hiveEscapePartition("a b/c:d%="); got != "a b%2Fc%3Ad%25%3D" {
		t.Fatalf("Hive path escaping = %q", got)
	}
}
