package glue

import (
	"context"
	"errors"
	"strings"

	api "stackd/internal/awsapi/glue"
)

func validateColumnStatistics(table TableRecord, stats api.ColumnStatistics) error {
	if stats.ColumnName == nil || stats.ColumnType == nil || stats.AnalyzedTime == nil || stats.StatisticsData == nil || stats.StatisticsData.Type == nil {
		return failure("InvalidInputException", "Column statistics require name, type, analyzed time, and statistics data.")
	}
	actual := ""
	if table.Table.StorageDescriptor != nil {
		for _, column := range table.Table.StorageDescriptor.Columns {
			if value(column.Name) == value(stats.ColumnName) {
				actual = strings.ToLower(value(column.Type))
				break
			}
		}
	}
	for _, column := range table.Table.PartitionKeys {
		if value(column.Name) == value(stats.ColumnName) {
			actual = strings.ToLower(value(column.Type))
			break
		}
	}
	if actual == "" {
		return failure("EntityNotFoundException", "Column does not exist.")
	}
	if actual != strings.ToLower(value(stats.ColumnType)) {
		return failure("InvalidInputException", "Column type does not match the table schema.")
	}
	expected := ""
	switch {
	case actual == "boolean":
		expected = "BOOLEAN"
	case actual == "binary":
		expected = "BINARY"
	case actual == "date":
		expected = "DATE"
	case strings.HasPrefix(actual, "decimal"):
		expected = "DECIMAL"
	case actual == "float" || actual == "double":
		expected = "DOUBLE"
	case actual == "tinyint" || actual == "smallint" || actual == "int" || actual == "bigint" || actual == "long":
		expected = "LONG"
	case actual == "string" || strings.HasPrefix(actual, "char") || strings.HasPrefix(actual, "varchar"):
		expected = "STRING"
	default:
		return failure("InvalidInputException", "Statistics for this column type are not supported.")
	}
	data := stats.StatisticsData
	count := 0
	for _, present := range []bool{data.BinaryColumnStatisticsData != nil, data.BooleanColumnStatisticsData != nil, data.DateColumnStatisticsData != nil, data.DecimalColumnStatisticsData != nil, data.DoubleColumnStatisticsData != nil, data.LongColumnStatisticsData != nil, data.StringColumnStatisticsData != nil} {
		if present {
			count++
		}
	}
	valid := expected == "BINARY" && data.BinaryColumnStatisticsData != nil || expected == "BOOLEAN" && data.BooleanColumnStatisticsData != nil || expected == "DATE" && data.DateColumnStatisticsData != nil || expected == "DECIMAL" && data.DecimalColumnStatisticsData != nil || expected == "DOUBLE" && data.DoubleColumnStatisticsData != nil || expected == "LONG" && data.LongColumnStatisticsData != nil || expected == "STRING" && data.StringColumnStatisticsData != nil
	if count != 1 || !valid || value(data.Type) != expected {
		return failure("InvalidInputException", "Statistics data does not match the column type.")
	}
	return nil
}
func (s *Service) updateColumnStatisticsForTable(ctx context.Context, tx Transaction, in *api.UpdateColumnStatisticsForTableInput) (*api.UpdateColumnStatisticsForTableOutput, error) {
	key := tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName)
	table, err := s.partitionTable(ctx, tx, "UpdateColumnStatisticsForTable", key)
	if err != nil {
		return nil, err
	}
	out := &api.UpdateColumnStatisticsForTableOutput{Errors: api.ColumnStatisticsErrors{}}
	for _, stats := range in.ColumnStatisticsList {
		if err := validateColumnStatistics(table, stats); err != nil {
			out.Errors = append(out.Errors, api.ColumnStatisticsError{ColumnStatistics: new(stats), Error: catalogErrorDetail(err)})
			continue
		}
		if err := tx.PutColumnStatistics(ColumnStatisticsRecord{Key: ColumnStatisticsKey{TableKey: key, ColumnName: value(stats.ColumnName)}, Statistics: stats}); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (s *Service) getColumnStatisticsForTable(ctx context.Context, tx Transaction, in *api.GetColumnStatisticsForTableInput) (*api.GetColumnStatisticsForTableOutput, error) {
	key := tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName)
	if _, err := s.partitionTable(ctx, tx, "GetColumnStatisticsForTable", key); err != nil {
		return nil, err
	}
	out := &api.GetColumnStatisticsForTableOutput{ColumnStatisticsList: api.ColumnStatisticsList{}, Errors: api.ColumnErrors{}}
	for _, column := range in.ColumnNames {
		stats, err := tx.ColumnStatistics(ColumnStatisticsKey{TableKey: key, ColumnName: string(column)})
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out.ColumnStatisticsList = append(out.ColumnStatisticsList, stats.Statistics)
	}
	return out, nil
}
func (s *Service) deleteColumnStatisticsForTable(ctx context.Context, tx Transaction, in *api.DeleteColumnStatisticsForTableInput) (*api.DeleteColumnStatisticsForTableOutput, error) {
	key := tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName)
	if _, err := s.partitionTable(ctx, tx, "DeleteColumnStatisticsForTable", key); err != nil {
		return nil, err
	}
	stats := ColumnStatisticsKey{TableKey: key, ColumnName: value(in.ColumnName)}
	if _, err := tx.ColumnStatistics(stats); err != nil {
		return nil, err
	}
	return &api.DeleteColumnStatisticsForTableOutput{}, tx.DeleteColumnStatistics(stats)
}
