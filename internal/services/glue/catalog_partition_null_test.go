package glue_test

import (
	"reflect"
	"sort"
	"testing"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/glue"
)

// Glue stores string partition values rather than SQL NULLs. Trino476's real
// GlueExpressionUtil deliberately pushes SQL IS NULL as sentinel equality and
// IS NOT NULL as sentinel inequality; the native reader interprets the matched
// sentinel as NULL only after partition retrieval. The API must not implement
// the reader's Hive value coercion inside its generic expression evaluator.
// https://docs.aws.amazon.com/glue/latest/webapi/API_GetPartitions.html
// https://github.com/trinodb/trino/blob/476/plugin/trino-hive/src/main/java/io/trino/plugin/hive/metastore/glue/GlueExpressionUtil.java
func TestGluePartitionFiltersKeepStoredStringsSeparateFromSQLNull(t *testing.T) {
	ctx := catalogTestContext("123456789012", "us-east-1")
	service := glue.New(glue.Config{})
	defer service.Close()
	catalogTestCall[api.CreateDatabaseOutput](t, service, ctx, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("null_boundary"))}})
	catalogTestCall[api.CreateTableOutput](t, service, ctx, "CreateTable", &api.CreateTableInput{DatabaseName: new(api.NameString("null_boundary")), TableInput: &api.TableInput{Name: new(api.NameString("events")), PartitionKeys: api.ColumnList{{Name: new(api.NameString("zone")), Type: new(api.ColumnTypeString("string"))}}}})
	for _, stored := range []api.ValueString{"__HIVE_DEFAULT_PARTITION__", "west", "NULL", ""} {
		catalogTestCall[api.CreatePartitionOutput](t, service, ctx, "CreatePartition", &api.CreatePartitionInput{DatabaseName: new(api.NameString("null_boundary")), TableName: new(api.NameString("events")), PartitionInput: &api.PartitionInput{Values: api.ValueStringList{stored}}})
	}
	for _, test := range []struct {
		expression string
		values     []string
	}{
		{"(zone = '__HIVE_DEFAULT_PARTITION__')", []string{"__HIVE_DEFAULT_PARTITION__"}},
		{"(zone <> '__HIVE_DEFAULT_PARTITION__')", []string{"", "NULL", "west"}},
		{"zone IN ('__HIVE_DEFAULT_PARTITION__','west')", []string{"__HIVE_DEFAULT_PARTITION__", "west"}},
		{"zone BETWEEN '__HIVE_DEFAULT_PARTITION__' AND '__HIVE_DEFAULT_PARTITION__'", []string{"__HIVE_DEFAULT_PARTITION__"}},
		{"zone LIKE '__HIVE%'", []string{"__HIVE_DEFAULT_PARTITION__"}},
		{"zone IS NULL", []string{}},
		{"zone IS NOT NULL", []string{"", "NULL", "__HIVE_DEFAULT_PARTITION__", "west"}},
		{"zone = NULL", []string{}},
		{"zone <> NULL", []string{}},
		{"zone IN ('west',NULL)", []string{"west"}},
		{"zone NOT IN ('west',NULL)", []string{}},
		{"NOT (zone = '__HIVE_DEFAULT_PARTITION__')", []string{"", "NULL", "west"}},
		{"zone = 'NULL'", []string{"NULL"}},
	} {
		t.Run(test.expression, func(t *testing.T) {
			result := catalogTestCall[api.GetPartitionsOutput](t, service, ctx, "GetPartitions", &api.GetPartitionsInput{DatabaseName: new(api.NameString("null_boundary")), TableName: new(api.NameString("events")), Expression: new(api.PredicateString(test.expression))})
			values := make([]string, 0, len(result.Partitions))
			for _, partition := range result.Partitions {
				values = append(values, string(partition.Values[0]))
			}
			sort.Strings(values)
			expected := append([]string{}, test.values...)
			sort.Strings(expected)
			if !reflect.DeepEqual(values, expected) {
				t.Fatalf("GetPartitions(%q) = %q, want %q", test.expression, values, expected)
			}
		})
	}
}
