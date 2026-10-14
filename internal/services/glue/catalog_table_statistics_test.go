package glue_test

import (
	"path/filepath"
	"testing"
	"time"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/glue"
	"stackd/storage/sqlite"
	gluesqlite "stackd/storage/sqlite/glue"
)

func TestTableStatisticsDeletionNativeIdempotence(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := catalogTestContext("123456789012", "us-east-1")
			var repository glue.Repository = glue.NewMemoryRepository(nil)
			if backend == "sqlite" {
				db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "statistics.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repository = gluesqlite.New(db)
			}
			s := glue.New(glue.Config{Repository: repository})
			t.Cleanup(func() { _ = s.Close() })
			database, table, column := api.NameString("statistics"), api.NameString("written"), api.NameString("id")
			catalogTestCall[api.CreateDatabaseOutput](t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: &database}})
			catalogTestCall[api.CreateTableOutput](t, s, ctx, "CreateTable", &api.CreateTableInput{DatabaseName: &database, TableInput: &api.TableInput{Name: &table, StorageDescriptor: &api.StorageDescriptor{Columns: api.ColumnList{{Name: &column, Type: new(api.ColumnTypeString("int"))}}}}})
			statistics := api.ColumnStatistics{ColumnName: &column, ColumnType: new(api.TypeString("int")), AnalyzedTime: new(time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)), StatisticsData: &api.ColumnStatisticsData{Type: new(api.ColumnStatisticsType("LONG")), LongColumnStatisticsData: &api.LongColumnStatisticsData{MinimumValue: new(api.Long(1)), MaximumValue: new(api.Long(2)), NumberOfNulls: new(api.NonNegativeLong(0)), NumberOfDistinctValues: new(api.NonNegativeLong(2))}}}
			put := catalogTestCall[api.UpdateColumnStatisticsForTableOutput](t, s, ctx, "UpdateColumnStatisticsForTable", &api.UpdateColumnStatisticsForTableInput{DatabaseName: &database, TableName: &table, ColumnStatisticsList: api.UpdateColumnStatisticsList{statistics}})
			if len(put.Errors) != 0 {
				t.Fatal(put.Errors)
			}
			input := &api.DeleteColumnStatisticsForTableInput{DatabaseName: &database, TableName: &table, ColumnName: &column}
			catalogTestCall[api.DeleteColumnStatisticsForTableOutput](t, s, ctx, "DeleteColumnStatisticsForTable", input)
			// Native AWS accepts both repeated deletion and an unknown column
			// on an existing table. Trino uses this while committing fresh CTAS.
			catalogTestCall[api.DeleteColumnStatisticsForTableOutput](t, s, ctx, "DeleteColumnStatisticsForTable", input)
			input.ColumnName = new(api.NameString("absent"))
			catalogTestCall[api.DeleteColumnStatisticsForTableOutput](t, s, ctx, "DeleteColumnStatisticsForTable", input)
			got := catalogTestCall[api.GetColumnStatisticsForTableOutput](t, s, ctx, "GetColumnStatisticsForTable", &api.GetColumnStatisticsForTableInput{DatabaseName: &database, TableName: &table, ColumnNames: api.GetColumnNamesList{"id", "absent"}})
			if len(got.ColumnStatisticsList) != 0 || len(got.Errors) != 2 {
				t.Fatalf("deleted statistics or missing per-column errors: %+v", got)
			}
			missing := map[string]bool{"id": true, "absent": true}
			for _, failure := range got.Errors {
				if failure.ColumnName == nil || !missing[string(*failure.ColumnName)] || failure.Error == nil || failure.Error.ErrorCode == nil || *failure.Error.ErrorCode != "EntityNotFoundException" {
					t.Fatalf("invalid missing-statistics error: %+v", failure)
				}
				delete(missing, string(*failure.ColumnName))
			}
			retained := catalogTestCall[api.GetTableOutput](t, s, ctx, "GetTable", &api.GetTableInput{DatabaseName: &database, Name: &table})
			if retained.Table == nil || retained.Table.Name == nil || *retained.Table.Name != table {
				t.Fatal("statistics deletion changed the table")
			}
			catalogTestCall[api.DeleteTableOutput](t, s, ctx, "DeleteTable", &api.DeleteTableInput{DatabaseName: &database, Name: &table})
			catalogTestError(t, s, ctx, "DeleteColumnStatisticsForTable", input, "EntityNotFoundException")
		})
	}
}
