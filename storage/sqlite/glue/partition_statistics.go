package glue

import (
	api "stackd/internal/awsapi/glue"
	domain "stackd/internal/services/glue"
	"stackd/storage/sqlite/glue/internal/sqlcgen"
)

func decodePartitionColumnStatistics(row sqlcgen.GluePartitionColumnStatistic) (domain.PartitionColumnStatisticsRecord, error) {
	key := domain.PartitionColumnStatisticsKey{PartitionKey: domain.PartitionKey{TableKey: domain.TableKey{DatabaseKey: domain.DatabaseKey{CatalogKey: domain.CatalogKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, CatalogID: row.CatalogID}, Name: row.DatabaseName}, TableName: row.TableName}, Values: row.ValuesJson}, ColumnName: row.ColumnName}
	out := domain.PartitionColumnStatisticsRecord{Key: key, Statistics: api.ColumnStatistics{ColumnName: new(api.NameString(row.ColumnName)), ColumnType: new(api.TypeString(row.ColumnType)), AnalyzedTime: new(row.AnalyzedAt.UTC())}}
	if err := catalogDecode(row.StatisticsDataJson, &out.Statistics.StatisticsData); err != nil {
		return domain.PartitionColumnStatisticsRecord{}, err
	}
	return out, nil
}

func (r reader) PartitionColumnStatistics(key domain.PartitionColumnStatisticsKey) (domain.PartitionColumnStatisticsRecord, error) {
	row, err := r.q.GetGluePartitionColumnStatistics(r.ctx, sqlcgen.GetGluePartitionColumnStatisticsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, ValuesJson: key.Values, ColumnName: key.ColumnName})
	if err != nil {
		return domain.PartitionColumnStatisticsRecord{}, missing(err)
	}
	return decodePartitionColumnStatistics(row)
}

func (r reader) PartitionStatistics(key domain.PartitionKey) ([]domain.PartitionColumnStatisticsRecord, error) {
	rows, err := r.q.ListGluePartitionStatistics(r.ctx, sqlcgen.ListGluePartitionStatisticsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, ValuesJson: key.Values})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PartitionColumnStatisticsRecord, 0, len(rows))
	for _, row := range rows {
		record, err := decodePartitionColumnStatistics(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (w writer) PutPartitionColumnStatistics(row domain.PartitionColumnStatisticsRecord) error {
	key := row.Key
	data, err := catalogEncode(row.Statistics.StatisticsData)
	if err != nil {
		return err
	}
	return w.q.PutGluePartitionColumnStatistics(w.ctx, sqlcgen.PutGluePartitionColumnStatisticsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, ValuesJson: key.Values, ColumnName: key.ColumnName, ColumnType: catalogValue(row.Statistics.ColumnType), AnalyzedAt: catalogRequiredTime(row.Statistics.AnalyzedTime), StatisticsDataJson: data})
}

func (w writer) DeletePartitionColumnStatistics(key domain.PartitionColumnStatisticsKey) error {
	return w.q.DeleteGluePartitionColumnStatistics(w.ctx, sqlcgen.DeleteGluePartitionColumnStatisticsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, ValuesJson: key.Values, ColumnName: key.ColumnName})
}

func (w writer) DeletePartitionStatistics(key domain.PartitionKey) error {
	return w.q.DeleteGluePartitionStatistics(w.ctx, sqlcgen.DeleteGluePartitionStatisticsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, ValuesJson: key.Values})
}

func (w writer) DeletePartitionColumnStatisticsForColumn(key domain.ColumnStatisticsKey) error {
	return w.q.DeleteGluePartitionColumnStatisticsForColumn(w.ctx, sqlcgen.DeleteGluePartitionColumnStatisticsForColumnParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, ColumnName: key.ColumnName})
}
