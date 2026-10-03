package glue_test

import (
	"testing"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/glue"
)

// Primary reference: resource-links-glue-apis.html. Deleting links must never
// delete their targets; current IAM applies to both identities on every access.
func TestCatalogResourceLinksFollowOnlyPermittedTargets(t *testing.T) {
	ctx := catalogTestContext("123456789012", "us-east-1")
	s := glue.New(glue.Config{})
	defer s.Close()
	for _, name := range []string{"target", "local"} {
		catalogTestCall[api.CreateDatabaseOutput](t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString(name))}})
	}
	catalogTestCall[api.CreateTableOutput](t, s, ctx, "CreateTable", &api.CreateTableInput{DatabaseName: new(api.NameString("target")), TableInput: &api.TableInput{Name: new(api.NameString("data")), Description: new(api.DescriptionString("original")), PartitionKeys: api.ColumnList{{Name: new(api.NameString("day")), Type: new(api.ColumnTypeString("string"))}}}})
	catalogTestCall[api.CreateDatabaseOutput](t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("database_link")), TargetDatabase: &api.DatabaseIdentifier{DatabaseName: new(api.NameString("target"))}}})
	catalogTestCall[api.CreateTableOutput](t, s, ctx, "CreateTable", &api.CreateTableInput{DatabaseName: new(api.NameString("local")), TableInput: &api.TableInput{Name: new(api.NameString("table_link")), TargetTable: &api.TableIdentifier{DatabaseName: new(api.NameString("target")), Name: new(api.NameString("data"))}}})
	linked := catalogTestCall[api.GetTableOutput](t, s, ctx, "GetTable", &api.GetTableInput{DatabaseName: new(api.NameString("local")), Name: new(api.NameString("table_link"))})
	if catalogTestValue(linked.Table.Name) != "data" || catalogTestValue(linked.Table.Description) != "original" {
		t.Fatalf("table link did not return target: %+v", linked.Table)
	}
	catalogTestCall[api.CreatePartitionOutput](t, s, ctx, "CreatePartition", &api.CreatePartitionInput{DatabaseName: new(api.NameString("local")), TableName: new(api.NameString("table_link")), PartitionInput: &api.PartitionInput{Values: api.ValueStringList{"2026-09-26"}}})
	partition := catalogTestCall[api.GetPartitionOutput](t, s, ctx, "GetPartition", &api.GetPartitionInput{DatabaseName: new(api.NameString("database_link")), TableName: new(api.NameString("data")), PartitionValues: api.ValueStringList{"2026-09-26"}})
	if catalogTestValue(partition.Partition.DatabaseName) != "target" {
		t.Fatalf("database link partition identity=%+v", partition.Partition)
	}
	catalogTestCall[api.UpdateTableOutput](t, s, ctx, "UpdateTable", &api.UpdateTableInput{DatabaseName: new(api.NameString("local")), TableInput: &api.TableInput{Name: new(api.NameString("table_link")), Description: new(api.DescriptionString("updated")), PartitionKeys: api.ColumnList{{Name: new(api.NameString("day")), Type: new(api.ColumnTypeString("string"))}}}})
	target := catalogTestCall[api.GetTableOutput](t, s, ctx, "GetTable", &api.GetTableInput{DatabaseName: new(api.NameString("target")), Name: new(api.NameString("data"))})
	if catalogTestValue(target.Table.Description) != "updated" || catalogTestValue(target.Table.VersionId) != "1" {
		t.Fatalf("link update did not change target: %+v", target.Table)
	}
	deny := api.PolicyJsonString(`{"Statement":{"Effect":"Deny","Principal":"*","Action":"glue:GetTable","Resource":"arn:aws:glue:us-east-1:123456789012:table/target/data"}}`)
	catalogTestCall[api.PutResourcePolicyOutput](t, s, ctx, "PutResourcePolicy", &api.PutResourcePolicyInput{PolicyInJson: &deny})
	catalogTestError(t, s, ctx, "GetTable", &api.GetTableInput{DatabaseName: new(api.NameString("local")), Name: new(api.NameString("table_link"))}, "AccessDeniedException")
	catalogTestCall[api.DeleteResourcePolicyOutput](t, s, ctx, "DeleteResourcePolicy", &api.DeleteResourcePolicyInput{})
	catalogTestCall[api.DeleteTableOutput](t, s, ctx, "DeleteTable", &api.DeleteTableInput{DatabaseName: new(api.NameString("local")), Name: new(api.NameString("table_link"))})
	catalogTestCall[api.DeleteDatabaseOutput](t, s, ctx, "DeleteDatabase", &api.DeleteDatabaseInput{Name: new(api.NameString("database_link"))})
	retained := catalogTestCall[api.GetPartitionOutput](t, s, ctx, "GetPartition", &api.GetPartitionInput{DatabaseName: new(api.NameString("target")), TableName: new(api.NameString("data")), PartitionValues: api.ValueStringList{"2026-09-26"}})
	if retained.Partition == nil || retained.Partition.Values[0] != "2026-09-26" {
		t.Fatal("deleting resource links deleted target partition")
	}
	// A database link may expose a table link, but cannot follow both for writes.
	catalogTestCall[api.CreateTableOutput](t, s, ctx, "CreateTable", &api.CreateTableInput{DatabaseName: new(api.NameString("local")), TableInput: &api.TableInput{Name: new(api.NameString("table_link")), TargetTable: &api.TableIdentifier{DatabaseName: new(api.NameString("target")), Name: new(api.NameString("data"))}}})
	catalogTestCall[api.CreateDatabaseOutput](t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("dual")), TargetDatabase: &api.DatabaseIdentifier{DatabaseName: new(api.NameString("local"))}}})
	empty := catalogTestCall[api.GetPartitionsOutput](t, s, ctx, "GetPartitions", &api.GetPartitionsInput{DatabaseName: new(api.NameString("dual")), TableName: new(api.NameString("table_link"))})
	if len(empty.Partitions) != 0 {
		t.Fatal("dual links exposed target partitions")
	}
	catalogTestError(t, s, ctx, "CreatePartition", &api.CreatePartitionInput{DatabaseName: new(api.NameString("dual")), TableName: new(api.NameString("table_link")), PartitionInput: &api.PartitionInput{Values: api.ValueStringList{"other"}}}, "InvalidInputException")
}
