package glue

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
)

func tableDescription(key TableKey, input *api.TableInput) api.Table {
	out := api.Table{Name: new(api.NameString(key.TableName)), DatabaseName: new(api.NameString(key.Name)), CatalogId: new(api.CatalogIdString(key.CatalogID)), Description: input.Description, Owner: input.Owner, Parameters: input.Parameters, PartitionKeys: input.PartitionKeys, Retention: input.Retention, StorageDescriptor: catalogStorageDescriptor(input.StorageDescriptor), TableType: input.TableType, TargetTable: input.TargetTable, ViewExpandedText: input.ViewExpandedText, ViewOriginalText: input.ViewOriginalText, LastAccessTime: input.LastAccessTime, LastAnalyzedTime: input.LastAnalyzedTime, IsRegisteredWithLakeFormation: new(api.Boolean(false)), IsMultiDialectView: new(api.NullableBoolean(false)), IsMaterializedView: new(api.NullableBoolean(false))}
	if out.Retention == nil {
		out.Retention = new(api.NonNegativeInteger(0))
	}
	return out
}
func catalogStorageDescriptor(input *api.StorageDescriptor) *api.StorageDescriptor {
	if input == nil {
		return nil
	}
	out := *input
	if out.Compressed == nil {
		out.Compressed = new(api.Boolean(false))
	}
	if out.NumberOfBuckets == nil {
		out.NumberOfBuckets = new(api.Integer(0))
	}
	if out.StoredAsSubDirectories == nil {
		out.StoredAsSubDirectories = new(api.Boolean(false))
	}
	if out.SortColumns == nil {
		out.SortColumns = api.OrderList{}
	}
	return &out
}
func validateTableInput(input *api.TableInput) error {
	if input == nil || value(input.Name) == "" {
		return failure("InvalidInputException", "TableInput.Name is required.")
	}
	// TODO: Comeback Lake Formation governed transactions and multi-dialect view validation require the Lake Formation/query owners.
	if value(input.TableType) == "GOVERNED" || input.ViewDefinition != nil {
		return unsupported("Governed tables and multi-dialect view definitions are not supported.")
	}
	names := map[string]bool{}
	if input.StorageDescriptor != nil {
		for _, column := range input.StorageDescriptor.Columns {
			name := strings.ToLower(value(column.Name))
			if names[name] {
				return failure("InvalidInputException", "Duplicate column name.")
			}
			names[name] = true
		}
	}
	for _, column := range input.PartitionKeys {
		name := strings.ToLower(value(column.Name))
		if names[name] {
			return failure("InvalidInputException", "Duplicate column or partition key name.")
		}
		names[name] = true
		typ := strings.ToLower(value(column.Type))
		if strings.ContainsAny(typ, "<>") {
			return failure("InvalidInputException", "Partition keys must have primitive types.")
		}
	}
	return nil
}
func (s *Service) createTable(ctx context.Context, tx Transaction, in *api.CreateTableInput) (*api.CreateTableOutput, error) {
	if err := validateTableInput(in.TableInput); err != nil {
		return nil, err
	}
	key := tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableInput.Name)
	if err := s.authorizeTable(ctx, tx, "CreateTable", key); err != nil {
		return nil, err
	}
	if in.TransactionId != nil || in.OpenTableFormatInput != nil {
		return nil, unsupported("Transactional and open table format creation requires its native table format owner.")
	}
	if _, err := tx.Database(key.DatabaseKey); err != nil {
		return nil, err
	}
	if _, err := tx.Table(key); err == nil {
		return nil, failure("AlreadyExistsException", "Table already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := s.clock.Now().UTC()
	record := TableRecord{Key: key, Table: tableDescription(key, in.TableInput)}
	record.Table.CreateTime = &now
	record.Table.UpdateTime = &now
	record.Table.VersionId = new(api.VersionString("0"))
	record.Table.CreatedBy = new(api.NameString(awsctx.FromContext(ctx).PrincipalARN))
	if err := tx.PutTable(record); err != nil {
		return nil, err
	}
	if err := tx.PutTableVersion(TableVersionRecord{Key: TableVersionKey{TableKey: key, Version: 0}, Table: record.Table}); err != nil {
		return nil, err
	}
	for _, index := range in.PartitionIndexes {
		if err := s.createIndex(tx, record, index); err != nil {
			return nil, err
		}
	}
	return &api.CreateTableOutput{}, nil
}
func (s *Service) getTable(ctx context.Context, tx Transaction, in *api.GetTableInput) (*api.GetTableOutput, error) {
	key := tableKey(ctx, in.CatalogId, in.DatabaseName, in.Name)
	if err := s.authorizeTable(ctx, tx, "GetTable", key); err != nil {
		return nil, err
	}
	if in.TransactionId != nil {
		return nil, unsupported("Lake Formation transactions are not supported.")
	}
	record, err := tableAt(tx, key, in.QueryAsOfTime)
	if err != nil {
		return nil, err
	}
	table, err := projectTable(record.Table, in.AttributesToGet)
	if err != nil {
		return nil, err
	}
	return &api.GetTableOutput{Table: &table}, nil
}
func projectTable(table api.Table, attributes api.TableAttributesList) (api.Table, error) {
	if len(attributes) == 0 || slices.Contains(attributes, api.TableAttributesDEFAULT) {
		return table, nil
	}
	if !slices.Contains(attributes, api.TableAttributesNAME) {
		return api.Table{}, failure("InvalidInputException", "AttributesToGet must include NAME.")
	}
	projected := api.Table{Name: table.Name}
	if slices.Contains(attributes, api.TableAttributesTABLE_TYPE) {
		projected.TableType = table.TableType
	}
	if slices.Contains(attributes, api.TableAttributesLATEST_ICEBERG_METADATA) {
		return api.Table{}, unsupported("Iceberg metadata is not available without the native table format owner.")
	}
	return projected, nil
}
func tableAt(tx Reader, key TableKey, at *time.Time) (TableRecord, error) {
	record, err := tx.Table(key)
	if err != nil || at == nil {
		return record, err
	}
	versions, err := tx.TableVersions(key)
	if err != nil {
		return TableRecord{}, err
	}
	for i := len(versions) - 1; i >= 0; i-- {
		v := versions[i]
		when := v.Table.UpdateTime
		if when != nil && !when.After(*at) {
			record.Table = v.Table
			record.Version = v.Key.Version
			return record, nil
		}
	}
	return TableRecord{}, ErrNotFound
}
func (s *Service) getTables(ctx context.Context, tx Transaction, in *api.GetTablesInput) (*api.GetTablesOutput, error) {
	key := databaseKey(ctx, in.CatalogId, in.DatabaseName)
	if err := s.authorizeDatabase(ctx, tx, "GetTables", key); err != nil {
		return nil, err
	}
	if _, err := tx.Database(key); err != nil {
		return nil, err
	}
	if in.TransactionId != nil {
		return nil, unsupported("Lake Formation transactions are not supported.")
	}
	filter, err := catalogNameFilter(value(in.Expression))
	if err != nil {
		return nil, err
	}
	binding := catalogPageBinding("GetTables", key.ARN(), value(in.Expression))
	after, err := catalogPageAfter(in.NextToken, binding)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Tables(key)
	if err != nil {
		return nil, err
	}
	out := &api.GetTablesOutput{TableList: api.TableList{}}
	limit := catalogPageSize(in.MaxResults)
	for _, row := range rows {
		if row.Key.TableName <= after || filter != nil && !filter.MatchString(row.Key.TableName) {
			continue
		}
		if err := s.authorizeTable(ctx, tx, "GetTables", row.Key); err != nil {
			if wireError(err).Code == "AccessDeniedException" {
				continue
			}
			return nil, err
		}
		if in.QueryAsOfTime != nil {
			row, err = tableAt(tx, row.Key, in.QueryAsOfTime)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
		}
		if len(out.TableList) == limit {
			out.NextToken = catalogNextToken(binding, value(out.TableList[len(out.TableList)-1].Name))
			break
		}
		table, err := projectTable(row.Table, in.AttributesToGet)
		if err != nil {
			return nil, err
		}
		out.TableList = append(out.TableList, table)
	}
	return out, nil
}
func (s *Service) updateTable(ctx context.Context, tx Transaction, in *api.UpdateTableInput) (*api.UpdateTableOutput, error) {
	if err := validateTableInput(in.TableInput); err != nil {
		return nil, err
	}
	name := in.TableInput.Name
	if in.Name != nil {
		name = in.Name
	}
	key := tableKey(ctx, in.CatalogId, in.DatabaseName, name)
	if err := s.authorizeTable(ctx, tx, "UpdateTable", key); err != nil {
		return nil, err
	}
	if in.TransactionId != nil || in.UpdateOpenTableFormatInput != nil || in.ViewUpdateAction != nil {
		return nil, unsupported("Transactional/open-format/view updates require their native owners.")
	}
	record, err := tx.Table(key)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(value(in.TableInput.Name)) != key.TableName {
		return nil, failure("InvalidInputException", "Table name cannot be changed.")
	}
	if in.VersionId != nil && value(in.VersionId) != strconv.FormatInt(record.Version, 10) {
		return nil, failure("ConcurrentModificationException", "Table version has changed.")
	}
	if err := removeObsoleteColumnStatistics(tx, record, in.TableInput); err != nil {
		return nil, err
	}
	if in.SkipArchive != nil && bool(*in.SkipArchive) {
		if err := tx.DeleteTableVersion(TableVersionKey{TableKey: key, Version: record.Version}); err != nil {
			return nil, err
		}
	}
	updated := tableDescription(key, in.TableInput)
	updated.CreateTime = record.Table.CreateTime
	updated.CreatedBy = record.Table.CreatedBy
	updated.UpdateTime = new(s.clock.Now().UTC())
	record.Version++
	updated.VersionId = new(api.VersionString(strconv.FormatInt(record.Version, 10)))
	record.Table = updated
	if err := tx.PutTable(record); err != nil {
		return nil, err
	}
	return &api.UpdateTableOutput{}, tx.PutTableVersion(TableVersionRecord{Key: TableVersionKey{TableKey: key, Version: record.Version}, Table: record.Table})
}
func (s *Service) deleteTable(ctx context.Context, tx Transaction, in *api.DeleteTableInput) (*api.DeleteTableOutput, error) {
	key := tableKey(ctx, in.CatalogId, in.DatabaseName, in.Name)
	if err := s.authorizeTable(ctx, tx, "DeleteTable", key); err != nil {
		return nil, err
	}
	if in.TransactionId != nil {
		return nil, unsupported("Lake Formation transactions are not supported.")
	}
	if err := deleteTableContents(tx, key); err != nil {
		return nil, err
	}
	return &api.DeleteTableOutput{}, nil
}
func deleteTableContents(tx Transaction, key TableKey) error {
	table, err := tx.Table(key)
	if err != nil {
		return err
	}
	partitions, err := tx.Partitions(key)
	if err != nil {
		return err
	}
	versions, err := tx.TableVersions(key)
	if err != nil {
		return err
	}
	indexes, err := tx.PartitionIndexes(key)
	if err != nil {
		return err
	}
	for _, row := range partitions {
		if err := deletePartitionContents(tx, row.Key); err != nil {
			return err
		}
	}
	for _, row := range versions {
		if err := tx.DeleteTableVersion(row.Key); err != nil {
			return err
		}
	}
	for _, row := range indexes {
		if err := tx.DeletePartitionIndex(row.Key); err != nil {
			return err
		}
	}
	columns := table.Table.PartitionKeys
	if table.Table.StorageDescriptor != nil {
		columns = append(slices.Clone(columns), table.Table.StorageDescriptor.Columns...)
	}
	for _, column := range columns {
		if err := tx.DeleteColumnStatistics(ColumnStatisticsKey{TableKey: key, ColumnName: value(column.Name)}); err != nil {
			return err
		}
	}
	return tx.DeleteTable(key)
}
func (s *Service) batchDeleteTable(ctx context.Context, tx Transaction, in *api.BatchDeleteTableInput) (*api.BatchDeleteTableOutput, error) {
	if in.TransactionId != nil {
		return nil, unsupported("Lake Formation transactions are not supported.")
	}
	out := &api.BatchDeleteTableOutput{Errors: api.TableErrors{}}
	database := databaseKey(ctx, in.CatalogId, in.DatabaseName)
	event := CatalogEvent{Scope: database.Scope, CatalogID: database.CatalogID, DatabaseName: database.Name, Operation: "BatchDeleteTable"}
	for _, name := range in.TablesToDelete {
		key := TableKey{DatabaseKey: database, TableName: strings.ToLower(string(name))}
		err := s.authorizeTable(ctx, tx, "BatchDeleteTable", key)
		if err == nil {
			err = deleteTableContents(tx, key)
		}
		if err != nil {
			if wireError(err).StatusCode >= 500 {
				return nil, err
			}
			out.Errors = append(out.Errors, api.TableError{TableName: new(api.NameString(name)), ErrorDetail: catalogErrorDetail(err)})
		} else if s.catalogEvents != nil {
			event.ChangedTables = append(event.ChangedTables, key.TableName)
		}
	}
	if len(event.ChangedTables) > 0 {
		if err := s.publishCatalogEvent(ctx, event); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (s *Service) getTableVersion(ctx context.Context, tx Transaction, in *api.GetTableVersionInput) (*api.GetTableVersionOutput, error) {
	key := tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName)
	if err := s.authorizeTable(ctx, tx, "GetTableVersion", key); err != nil {
		return nil, err
	}
	table, err := tx.Table(key)
	if err != nil {
		return nil, err
	}
	version := table.Version
	if in.VersionId != nil {
		version, err = strconv.ParseInt(value(in.VersionId), 10, 64)
		if err != nil || version < 0 {
			return nil, failure("InvalidInputException", "Invalid table version.")
		}
	}
	record, err := tx.TableVersion(TableVersionKey{TableKey: key, Version: version})
	if err != nil {
		return nil, err
	}
	return &api.GetTableVersionOutput{TableVersion: &api.TableVersion{Table: &record.Table, VersionId: new(api.VersionString(strconv.FormatInt(version, 10)))}}, nil
}
func (s *Service) getTableVersions(ctx context.Context, tx Transaction, in *api.GetTableVersionsInput) (*api.GetTableVersionsOutput, error) {
	key := tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName)
	if err := s.authorizeTable(ctx, tx, "GetTableVersions", key); err != nil {
		return nil, err
	}
	if _, err := tx.Table(key); err != nil {
		return nil, err
	}
	rows, err := tx.TableVersions(key)
	if err != nil {
		return nil, err
	}
	slices.Reverse(rows)
	binding := catalogPageBinding("GetTableVersions", key.ARN())
	after, err := catalogPageAfter(in.NextToken, binding)
	if err != nil {
		return nil, err
	}
	var last int64
	if after != "" {
		last, err = strconv.ParseInt(after, 10, 64)
		if err != nil {
			return nil, failure("InvalidInputException", "Invalid version continuation token.")
		}
	}
	out := &api.GetTableVersionsOutput{TableVersions: api.GetTableVersionsList{}}
	limit := catalogPageSize(in.MaxResults)
	for _, row := range rows {
		if after != "" && row.Key.Version >= last {
			continue
		}
		if len(out.TableVersions) == limit {
			out.NextToken = catalogNextToken(binding, value(out.TableVersions[len(out.TableVersions)-1].VersionId))
			break
		}
		out.TableVersions = append(out.TableVersions, api.TableVersion{Table: new(row.Table), VersionId: new(api.VersionString(strconv.FormatInt(row.Key.Version, 10)))})
	}
	return out, nil
}
func (s *Service) deleteTableVersion(ctx context.Context, tx Transaction, in *api.DeleteTableVersionInput) (*api.DeleteTableVersionOutput, error) {
	key := tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableName)
	if err := s.authorizeTable(ctx, tx, "DeleteTableVersion", key); err != nil {
		return nil, err
	}
	table, err := tx.Table(key)
	if err != nil {
		return nil, err
	}
	version, err := strconv.ParseInt(value(in.VersionId), 10, 64)
	if err != nil || version < 0 {
		return nil, failure("InvalidInputException", "Invalid table version.")
	}
	if version == table.Version {
		return nil, failure("InvalidInputException", "VersionId cannot be equal to the latest.")
	}
	versionKey := TableVersionKey{TableKey: key, Version: version}
	if _, err := tx.TableVersion(versionKey); err != nil {
		return nil, err
	}
	return &api.DeleteTableVersionOutput{}, tx.DeleteTableVersion(versionKey)
}
func removeObsoleteColumnStatistics(tx Transaction, old TableRecord, input *api.TableInput) error {
	columns := make(map[string]string, len(input.PartitionKeys))
	for _, column := range input.PartitionKeys {
		columns[value(column.Name)] = value(column.Type)
	}
	if input.StorageDescriptor != nil {
		for _, column := range input.StorageDescriptor.Columns {
			columns[value(column.Name)] = value(column.Type)
		}
	}
	remove := func(list api.ColumnList) error {
		for _, column := range list {
			typ, ok := columns[value(column.Name)]
			if !ok || typ != value(column.Type) {
				if err := tx.DeleteColumnStatistics(ColumnStatisticsKey{TableKey: old.Key, ColumnName: value(column.Name)}); err != nil {
					return err
				}
				if err := tx.DeletePartitionColumnStatisticsForColumn(ColumnStatisticsKey{TableKey: old.Key, ColumnName: value(column.Name)}); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := remove(old.Table.PartitionKeys); err != nil {
		return err
	}
	if old.Table.StorageDescriptor != nil {
		return remove(old.Table.StorageDescriptor.Columns)
	}
	return nil
}
