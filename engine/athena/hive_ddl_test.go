package athena

import (
	"strings"
	"testing"
)

func TestHiveIcebergTypedTransforms(t *testing.T) {
	request := Request{AccountID: "123456789012", Catalog: "awsdatacatalog", CatalogID: "123456789012", Database: "fixture"}
	plan := &HiveDDL{Kind: "CREATE_TABLE", Identifier: []string{"fixture", "transformed"}, Location: "s3://fixture-data/iceberg/", Properties: map[string]string{"table_type": "ICEBERG"}, Columns: []DDLColumn{{Name: "id", Type: "bigint", TrinoType: "bigint"}, {Name: "ts", Type: "timestamp", TrinoType: "timestamp(3)"}}}
	for _, transform := range []DDLTransform{{Name: "identity", Fields: []string{"id"}}, {Name: "bucket", Fields: []string{"id"}, Count: 4}, {Name: "truncate", Fields: []string{"id"}, Count: 10}, {Name: "year", Fields: []string{"ts"}}, {Name: "months", Fields: []string{"ts"}}, {Name: "day", Fields: []string{"ts"}}, {Name: "hours", Fields: []string{"ts"}}} {
		plan.PartitionTransforms = []DDLTransform{transform}
		sql, err := hiveNativeDDL(plan, request)
		if err != nil || !strings.Contains(sql, "partitioning=ARRAY[") {
			t.Fatalf("%+v: %q %v", transform, sql, err)
		}
		switch transform.Name {
		case "bucket":
			if !strings.Contains(sql, `bucket("id", 4)`) {
				t.Fatal(sql)
			}
		case "truncate":
			if !strings.Contains(sql, `truncate("id", 10)`) {
				t.Fatal(sql)
			}
		case "months":
			if !strings.Contains(sql, `month("ts")`) {
				t.Fatal(sql)
			}
		}
	}
	for _, invalid := range []DDLTransform{{Name: "bucket", Fields: []string{"id"}, Count: 0}, {Name: "unknown", Fields: []string{"id"}}, {Name: "bucket", Fields: []string{"id", "ts"}, Count: 4}} {
		plan.PartitionTransforms = []DDLTransform{invalid}
		if _, err := hiveNativeDDL(plan, request); err == nil {
			t.Fatalf("invalid transform accepted: %+v", invalid)
		}
	}
	plan.PartitionTransforms = nil
	plan.External = true
	if _, err := hiveNativeDDL(plan, request); err == nil {
		t.Fatal("Iceberg EXTERNAL keyword accepted")
	}
}

func TestHiveIcebergPartitionReferencesMatchNativeColumnCase(t *testing.T) {
	request := Request{AccountID: "123456789012", Catalog: "awsdatacatalog", CatalogID: "123456789012", Database: "fixture"}
	plan := &HiveDDL{Kind: "CREATE_TABLE", Identifier: []string{"fixture", "mixed"}, Location: "s3://fixture-data/mixed/", Properties: map[string]string{"table_type": "ICEBERG"}, Columns: []DDLColumn{{Name: "ID", Type: "bigint", TrinoType: "bigint"}, {Name: "Created_At", Type: "timestamp", TrinoType: "timestamp(3)"}}}
	plan.PartitionTransforms = []DDLTransform{{Name: "identity", Fields: []string{"ID"}}, {Name: "bucket", Fields: []string{"Id"}, Count: 4}, {Name: "day", Fields: []string{"CREATED_AT"}}}
	sql, err := icebergDDL(plan, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`"id" bigint`, `"created_at" timestamp(3)`, `'"id"'`, `bucket("id", 4)`, `day("created_at")`} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("missing %q in %s", fragment, sql)
		}
	}
	plan.PartitionTransforms = nil
	plan.PartitionColumns = []string{"ID"}
	sql, err = icebergDDL(plan, request)
	if err != nil || !strings.Contains(sql, "partitioning=ARRAY['id']") {
		t.Fatalf("legacy identity case: %s %v", sql, err)
	}
}
