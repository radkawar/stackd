package glue

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/glue"
)

func (s *Service) statisticsPartition(ctx context.Context, tx Reader, action string, key TableKey, values api.ValueStringList) (TableRecord, PartitionRecord, error) {
	if err := s.authorizeTable(ctx, tx, action, key); err != nil {
		return TableRecord{}, PartitionRecord{}, err
	}
	table, err := tx.Table(key)
	if err != nil {
		return TableRecord{}, PartitionRecord{}, err
	}
	if err := validatePartitionValues(table, values); err != nil {
		return TableRecord{}, PartitionRecord{}, err
	}
	partition, err := tx.Partition(PartitionKey{TableKey: key, Values: partitionValuesKey(values)})
	return table, partition, err
}

func partitionStatisticsSchema(table TableRecord, partition api.Partition) TableRecord {
	if partition.StorageDescriptor != nil && partition.StorageDescriptor.Columns != nil {
		table.Table.StorageDescriptor = partition.StorageDescriptor
	}
	return table
}

func (s *Service) getColumnStatisticsForPartition(ctx context.Context, tx Transaction, in *api.GetColumnStatisticsForPartitionInput) (*api.GetColumnStatisticsForPartitionOutput, error) {
	_, partition, err := s.statisticsPartition(ctx, tx, "GetColumnStatisticsForPartition", tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName), in.PartitionValues)
	if err != nil {
		return nil, err
	}
	out := &api.GetColumnStatisticsForPartitionOutput{ColumnStatisticsList: api.ColumnStatisticsList{}, Errors: api.ColumnErrors{}}
	for _, column := range in.ColumnNames {
		row, err := tx.PartitionColumnStatistics(PartitionColumnStatisticsKey{PartitionKey: partition.Key, ColumnName: string(column)})
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out.ColumnStatisticsList = append(out.ColumnStatisticsList, row.Statistics)
	}
	return out, nil
}

func (s *Service) updateColumnStatisticsForPartition(ctx context.Context, tx Transaction, in *api.UpdateColumnStatisticsForPartitionInput) (*api.UpdateColumnStatisticsForPartitionOutput, error) {
	table, partition, err := s.statisticsPartition(ctx, tx, "UpdateColumnStatisticsForPartition", tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName), in.PartitionValues)
	if err != nil {
		return nil, err
	}
	schema := partitionStatisticsSchema(table, partition.Partition)
	out := &api.UpdateColumnStatisticsForPartitionOutput{Errors: api.ColumnStatisticsErrors{}}
	for _, statistics := range in.ColumnStatisticsList {
		if err := validateColumnStatistics(schema, statistics); err != nil {
			out.Errors = append(out.Errors, api.ColumnStatisticsError{ColumnStatistics: new(statistics), Error: catalogErrorDetail(err)})
			continue
		}
		row := PartitionColumnStatisticsRecord{Key: PartitionColumnStatisticsKey{PartitionKey: partition.Key, ColumnName: value(statistics.ColumnName)}, Statistics: statistics}
		if err := tx.PutPartitionColumnStatistics(row); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Service) deleteColumnStatisticsForPartition(ctx context.Context, tx Transaction, in *api.DeleteColumnStatisticsForPartitionInput) (*api.DeleteColumnStatisticsForPartitionOutput, error) {
	_, partition, err := s.statisticsPartition(ctx, tx, "DeleteColumnStatisticsForPartition", tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName), in.PartitionValues)
	if err != nil {
		return nil, err
	}
	key := PartitionColumnStatisticsKey{PartitionKey: partition.Key, ColumnName: value(in.ColumnName)}
	if _, err := tx.PartitionColumnStatistics(key); err != nil {
		return nil, err
	}
	return &api.DeleteColumnStatisticsForPartitionOutput{}, tx.DeletePartitionColumnStatistics(key)
}

func deletePartitionContents(tx Transaction, key PartitionKey) error {
	if err := tx.DeletePartitionStatistics(key); err != nil {
		return err
	}
	return tx.DeletePartition(key)
}

func updatePartitionStatistics(tx Transaction, table TableRecord, old PartitionKey, next PartitionRecord) error {
	rows, err := tx.PartitionStatistics(old)
	if err != nil {
		return err
	}
	schema := partitionStatisticsSchema(table, next.Partition)
	for _, row := range rows {
		if err := validateColumnStatistics(schema, row.Statistics); err != nil {
			if err := tx.DeletePartitionColumnStatistics(row.Key); err != nil {
				return err
			}
			continue
		}
		if old != next.Key {
			if err := tx.DeletePartitionColumnStatistics(row.Key); err != nil {
				return err
			}
			row.Key.PartitionKey = next.Key
			if err := tx.PutPartitionColumnStatistics(row); err != nil {
				return err
			}
		}
	}
	return nil
}
