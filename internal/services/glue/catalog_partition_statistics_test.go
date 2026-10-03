package glue_test

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/glue"
	"stackd/storage/sqlite"
	gluesqlite "stackd/storage/sqlite/glue"
)

func TestPartitionColumnStatisticsPersistenceIsolationAndLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := catalogTestContext("123456789012", "us-east-1")
			var repository glue.Repository
			closeDB := func() {}
			var reopen func() glue.Repository
			if backend == "memory" {
				repository = glue.NewMemoryRepository(nil)
				reopen = func() glue.Repository { return repository }
			} else {
				path := filepath.Join(t.TempDir(), "partition-stats.sqlite")
				open := func() glue.Repository {
					db, err := sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					closeDB = func() {
						if err := db.Close(); err != nil {
							t.Error(err)
						}
					}
					return gluesqlite.New(db)
				}
				repository, reopen = open(), open
			}
			s := glue.New(glue.Config{Repository: repository})
			defer func() { _ = s.Close(); closeDB() }()
			database, name := api.NameString("stats"), api.NameString("sales")
			columns := api.ColumnList{{Name: new(api.NameString("amount")), Type: new(api.ColumnTypeString("bigint"))}, {Name: new(api.NameString("category")), Type: new(api.ColumnTypeString("string"))}}
			table := &api.TableInput{Name: &name, StorageDescriptor: &api.StorageDescriptor{Columns: columns}, PartitionKeys: api.ColumnList{{Name: new(api.NameString("year")), Type: new(api.ColumnTypeString("int"))}}}
			catalogTestCall[api.CreateDatabaseOutput](t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: &database}})
			createTable := func() {
				catalogTestCall[api.CreateTableOutput](t, s, ctx, "CreateTable", &api.CreateTableInput{DatabaseName: &database, TableInput: table})
			}
			createPartition := func(year string) {
				catalogTestCall[api.CreatePartitionOutput](t, s, ctx, "CreatePartition", &api.CreatePartitionInput{DatabaseName: &database, TableName: &name, PartitionInput: &api.PartitionInput{Values: api.ValueStringList{api.ValueString(year)}}})
			}
			getInput := func(year string) *api.GetColumnStatisticsForPartitionInput {
				return &api.GetColumnStatisticsForPartitionInput{DatabaseName: &database, TableName: &name, PartitionValues: api.ValueStringList{api.ValueString(year)}, ColumnNames: api.GetColumnNamesList{"category", "amount"}}
			}
			get := func(year string) *api.GetColumnStatisticsForPartitionOutput {
				return catalogTestCall[api.GetColumnStatisticsForPartitionOutput](t, s, ctx, "GetColumnStatisticsForPartition", getInput(year))
			}
			createTable()
			createPartition("2026")
			createPartition("2025")
			if out := get("2026"); len(out.ColumnStatisticsList) != 0 || len(out.Errors) != 0 {
				t.Fatalf("unexpected initial statistics: %+v", out)
			}
			catalogTestError(t, s, ctx, "GetColumnStatisticsForPartition", getInput("2024"), "EntityNotFoundException")
			catalogTestError(t, s, catalogTestContext("123456789012", "eu-west-1"), "GetColumnStatisticsForPartition", getInput("2026"), "EntityNotFoundException")
			foreign := getInput("2026")
			foreign.CatalogId = new(api.CatalogIdString("123456789012"))
			catalogTestError(t, s, catalogTestContext("210987654321", "us-east-1"), "GetColumnStatisticsForPartition", foreign, "AccessDeniedException")

			statistics := api.ColumnStatistics{ColumnName: new(api.NameString("amount")), ColumnType: new(api.TypeString("bigint")), AnalyzedTime: new(time.Date(2026, 9, 26, 14, 0, 0, 0, time.UTC)), StatisticsData: &api.ColumnStatisticsData{Type: new(api.ColumnStatisticsType("LONG")), LongColumnStatisticsData: &api.LongColumnStatisticsData{MinimumValue: new(api.Long(5)), MaximumValue: new(api.Long(45)), NumberOfNulls: new(api.NonNegativeLong(0)), NumberOfDistinctValues: new(api.NonNegativeLong(3))}}}
			put := func(year string) {
				out := catalogTestCall[api.UpdateColumnStatisticsForPartitionOutput](t, s, ctx, "UpdateColumnStatisticsForPartition", &api.UpdateColumnStatisticsForPartitionInput{DatabaseName: &database, TableName: &name, PartitionValues: api.ValueStringList{api.ValueString(year)}, ColumnStatisticsList: api.UpdateColumnStatisticsList{statistics}})
				if len(out.Errors) != 0 {
					t.Fatalf("update errors: %v", out.Errors)
				}
			}
			invalid := statistics
			invalid.ColumnName = new(api.NameString("category"))
			mixed := catalogTestCall[api.UpdateColumnStatisticsForPartitionOutput](t, s, ctx, "UpdateColumnStatisticsForPartition", &api.UpdateColumnStatisticsForPartitionInput{DatabaseName: &database, TableName: &name, PartitionValues: api.ValueStringList{"2026"}, ColumnStatisticsList: api.UpdateColumnStatisticsList{statistics, invalid}})
			if len(mixed.Errors) != 1 || catalogTestValue(mixed.Errors[0].ColumnStatistics.ColumnName) != "category" || catalogTestValue(mixed.Errors[0].Error.ErrorCode) != "InvalidInputException" {
				t.Fatalf("mixed statistics result: %v", mixed.Errors)
			}
			assertStatistics := func(year string) {
				out := get(year)
				if len(out.Errors) != 0 || len(out.ColumnStatisticsList) != 1 || !reflect.DeepEqual(out.ColumnStatisticsList[0], statistics) {
					t.Fatalf("retained %s statistics: %+v", year, out)
				}
			}
			assertStatistics("2026")
			if out := get("2025"); len(out.ColumnStatisticsList) != 0 {
				t.Fatalf("statistics crossed partition boundary: %+v", out)
			}
			_ = s.Close()
			closeDB()
			repository = reopen()
			s = glue.New(glue.Config{Repository: repository})
			assertStatistics("2026")

			// The native API requires GetPartition/UpdatePartition permissions, not the API operation names.
			policy := api.PolicyJsonString(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["glue:GetPartition","glue:UpdatePartition"],"Resource":"*"}]}`)
			catalogTestCall[api.PutResourcePolicyOutput](t, s, ctx, "PutResourcePolicy", &api.PutResourcePolicyInput{PolicyInJson: &policy})
			catalogTestError(t, s, ctx, "GetColumnStatisticsForPartition", getInput("2026"), "AccessDeniedException")
			catalogTestError(t, s, ctx, "UpdateColumnStatisticsForPartition", &api.UpdateColumnStatisticsForPartitionInput{DatabaseName: &database, TableName: &name, PartitionValues: api.ValueStringList{"2026"}, ColumnStatisticsList: api.UpdateColumnStatisticsList{statistics}}, "AccessDeniedException")
			catalogTestError(t, s, ctx, "DeleteColumnStatisticsForPartition", &api.DeleteColumnStatisticsForPartitionInput{DatabaseName: &database, TableName: &name, PartitionValues: api.ValueStringList{"2026"}, ColumnName: statistics.ColumnName}, "AccessDeniedException")
			catalogTestCall[api.DeleteResourcePolicyOutput](t, s, ctx, "DeleteResourcePolicy", &api.DeleteResourcePolicyInput{})
			catalogTestCall[api.UpdatePartitionOutput](t, s, ctx, "UpdatePartition", &api.UpdatePartitionInput{DatabaseName: &database, TableName: &name, PartitionValueList: api.BoundedPartitionValueList{"2026"}, PartitionInput: &api.PartitionInput{Values: api.ValueStringList{"2027"}}})
			assertStatistics("2027")
			catalogTestError(t, s, ctx, "GetColumnStatisticsForPartition", getInput("2026"), "EntityNotFoundException")
			deleteStatistics := &api.DeleteColumnStatisticsForPartitionInput{DatabaseName: &database, TableName: &name, PartitionValues: api.ValueStringList{"2027"}, ColumnName: statistics.ColumnName}
			catalogTestCall[api.DeleteColumnStatisticsForPartitionOutput](t, s, ctx, "DeleteColumnStatisticsForPartition", deleteStatistics)
			if out := get("2027"); len(out.ColumnStatisticsList) != 0 {
				t.Fatalf("deleted statistics retained: %+v", out)
			}
			catalogTestError(t, s, ctx, "DeleteColumnStatisticsForPartition", deleteStatistics, "EntityNotFoundException")
			put("2027")
			catalogTestCall[api.DeletePartitionOutput](t, s, ctx, "DeletePartition", &api.DeletePartitionInput{DatabaseName: &database, TableName: &name, PartitionValues: api.ValueStringList{"2027"}})
			createPartition("2027")
			if out := get("2027"); len(out.ColumnStatisticsList) != 0 {
				t.Fatalf("partition recreation resurrected statistics: %+v", out)
			}
			put("2027")
			catalogTestCall[api.UpdatePartitionOutput](t, s, ctx, "UpdatePartition", &api.UpdatePartitionInput{DatabaseName: &database, TableName: &name, PartitionValueList: api.BoundedPartitionValueList{"2027"}, PartitionInput: &api.PartitionInput{Values: api.ValueStringList{"2027"}, StorageDescriptor: &api.StorageDescriptor{Columns: api.ColumnList{{Name: statistics.ColumnName, Type: new(api.ColumnTypeString("string"))}}}}})
			if out := get("2027"); len(out.ColumnStatisticsList) != 0 {
				t.Fatalf("schema replacement retained incompatible statistics: %+v", out)
			}
			put("2025")
			catalogTestCall[api.DeleteTableOutput](t, s, ctx, "DeleteTable", &api.DeleteTableInput{DatabaseName: &database, Name: &name})
			createTable()
			createPartition("2025")
			if out := get("2025"); len(out.ColumnStatisticsList) != 0 {
				t.Fatalf("table recreation resurrected statistics: %+v", out)
			}
		})
	}
}
