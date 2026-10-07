package glue

import (
	api "stackd/internal/awsapi/glue"
	domain "stackd/internal/services/glue"
	"stackd/storage/sqlite/glue/internal/sqlcgen"
	"strconv"
	"time"
)

func catalogValue[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func catalogRequiredTime(v *time.Time) time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.UTC()
}
func catalogBoolean[T ~bool](v *T) int64 {
	if v != nil && bool(*v) {
		return 1
	}
	return 0
}
func decodeCatalog(row sqlcgen.GlueCatalog) (domain.CatalogRecord, error) {
	out := domain.CatalogRecord{Key: domain.CatalogKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, CatalogID: row.CatalogID}}
	out.CFNOwner = row.CfnOwner
	out.Catalog.CatalogId = new(api.CatalogIdString(row.CatalogID))
	out.Catalog.ResourceArn = new(api.ResourceArnString(out.Key.ARN()))
	out.Catalog.Name = new(api.CatalogNameString(row.Name))
	out.Catalog.Description = catalogString[api.DescriptionString](row.Description)
	out.Catalog.CreateTime = new(row.CreatedAt.UTC())
	out.Catalog.UpdateTime = new(row.UpdatedAt.UTC())
	if err := catalogDecode(row.ParametersJson, &out.Catalog.Parameters); err != nil {
		return out, err
	}
	if err := catalogDecode(row.DatabasePermissionsJson, &out.Catalog.CreateDatabaseDefaultPermissions); err != nil {
		return out, err
	}
	if err := catalogDecode(row.TablePermissionsJson, &out.Catalog.CreateTableDefaultPermissions); err != nil {
		return out, err
	}
	out.Catalog.AllowFullTableExternalDataAccess = catalogString[api.AllowFullTableExternalDataAccessEnum](row.FullTableAccess)
	if err := catalogDecode(row.TagsJson, &out.Tags); err != nil {
		return out, err
	}
	return out, nil
}
func (r reader) Catalog(key domain.CatalogKey) (domain.CatalogRecord, error) {
	row, err := r.q.GetGlueCatalog(r.ctx, sqlcgen.GetGlueCatalogParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID})
	if err != nil {
		return domain.CatalogRecord{}, missing(err)
	}
	return decodeCatalog(row)
}
func (w writer) DeleteCatalog(key domain.CatalogKey) error {
	return w.q.DeleteGlueCatalog(w.ctx, sqlcgen.DeleteGlueCatalogParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID})
}
func (r reader) Catalogs(key domain.Scope) ([]domain.CatalogRecord, error) {
	rows, err := r.q.ListGlueCatalogs(r.ctx, sqlcgen.ListGlueCatalogsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.CatalogRecord, 0, len(rows))
	for _, row := range rows {
		record, err := decodeCatalog(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func (w writer) PutCatalog(v domain.CatalogRecord) error {
	key := v.Key
	p := sqlcgen.PutGlueCatalogParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID}
	p.CfnOwner = v.CFNOwner
	p.Name = catalogValue(v.Catalog.Name)
	p.Description = catalogNullString(v.Catalog.Description)
	p.CreatedAt = catalogRequiredTime(v.Catalog.CreateTime)
	p.UpdatedAt = catalogRequiredTime(v.Catalog.UpdateTime)
	{
		encoded, err := catalogEncode(v.Catalog.Parameters)
		if err != nil {
			return err
		}
		p.ParametersJson = encoded
	}
	{
		encoded, err := catalogEncode(v.Catalog.CreateDatabaseDefaultPermissions)
		if err != nil {
			return err
		}
		p.DatabasePermissionsJson = encoded
	}
	{
		encoded, err := catalogEncode(v.Catalog.CreateTableDefaultPermissions)
		if err != nil {
			return err
		}
		p.TablePermissionsJson = encoded
	}
	p.FullTableAccess = catalogNullString(v.Catalog.AllowFullTableExternalDataAccess)
	{
		encoded, err := catalogEncode(v.Tags)
		if err != nil {
			return err
		}
		p.TagsJson = encoded
	}
	return w.q.PutGlueCatalog(w.ctx, p)
}
func decodeDatabase(row sqlcgen.GlueDatabase) (domain.DatabaseRecord, error) {
	out := domain.DatabaseRecord{Key: domain.DatabaseKey{CatalogKey: domain.CatalogKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, CatalogID: row.CatalogID}, Name: row.DatabaseName}}
	out.CFNOwner = row.CfnOwner
	out.Database.Name = new(api.NameString(row.DatabaseName))
	out.Database.CatalogId = new(api.CatalogIdString(row.CatalogID))
	out.Database.Description = catalogString[api.DescriptionString](row.Description)
	out.Database.LocationUri = catalogString[api.URI](row.LocationUri)
	out.Database.CreateTime = new(row.CreatedAt.UTC())
	if err := catalogDecode(row.ParametersJson, &out.Database.Parameters); err != nil {
		return out, err
	}
	if err := catalogDecode(row.DefaultPermissionsJson, &out.Database.CreateTableDefaultPermissions); err != nil {
		return out, err
	}
	if err := catalogDecode(row.TargetDatabaseJson, &out.Database.TargetDatabase); err != nil {
		return out, err
	}
	if err := catalogDecode(row.TagsJson, &out.Tags); err != nil {
		return out, err
	}
	return out, nil
}
func (r reader) Database(key domain.DatabaseKey) (domain.DatabaseRecord, error) {
	row, err := r.q.GetGlueDatabase(r.ctx, sqlcgen.GetGlueDatabaseParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name})
	if err != nil {
		return domain.DatabaseRecord{}, missing(err)
	}
	return decodeDatabase(row)
}
func (w writer) DeleteDatabase(key domain.DatabaseKey) error {
	return w.q.DeleteGlueDatabase(w.ctx, sqlcgen.DeleteGlueDatabaseParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name})
}
func (r reader) Databases(key domain.CatalogKey) ([]domain.DatabaseRecord, error) {
	rows, err := r.q.ListGlueDatabases(r.ctx, sqlcgen.ListGlueDatabasesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.DatabaseRecord, 0, len(rows))
	for _, row := range rows {
		record, err := decodeDatabase(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func (r reader) ForeignDatabases(scope domain.Scope) ([]domain.DatabaseRecord, error) {
	rows, err := r.q.ListGlueForeignDatabases(r.ctx, sqlcgen.ListGlueForeignDatabasesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.DatabaseRecord, 0, len(rows))
	for _, row := range rows {
		record, err := decodeDatabase(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func (w writer) PutDatabase(v domain.DatabaseRecord) error {
	key := v.Key
	p := sqlcgen.PutGlueDatabaseParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name}
	p.CfnOwner = v.CFNOwner
	p.Description = catalogNullString(v.Database.Description)
	p.LocationUri = catalogNullString(v.Database.LocationUri)
	p.CreatedAt = catalogRequiredTime(v.Database.CreateTime)
	{
		encoded, err := catalogEncode(v.Database.Parameters)
		if err != nil {
			return err
		}
		p.ParametersJson = encoded
	}
	{
		encoded, err := catalogEncode(v.Database.CreateTableDefaultPermissions)
		if err != nil {
			return err
		}
		p.DefaultPermissionsJson = encoded
	}
	{
		encoded, err := catalogEncode(v.Database.TargetDatabase)
		if err != nil {
			return err
		}
		p.TargetDatabaseJson = encoded
	}
	{
		encoded, err := catalogEncode(v.Tags)
		if err != nil {
			return err
		}
		p.TagsJson = encoded
	}
	return w.q.PutGlueDatabase(w.ctx, p)
}
func decodeTable(row sqlcgen.GlueTable) (domain.TableRecord, error) {
	out := domain.TableRecord{Key: domain.TableKey{DatabaseKey: domain.DatabaseKey{CatalogKey: domain.CatalogKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, CatalogID: row.CatalogID}, Name: row.DatabaseName}, TableName: row.TableName}}
	out.CFNOwner = row.CfnOwner
	out.Table.Name = new(api.NameString(row.TableName))
	out.Table.DatabaseName = new(api.NameString(row.DatabaseName))
	out.Table.CatalogId = new(api.CatalogIdString(row.CatalogID))
	out.Table.VersionId = new(api.VersionString(strconv.FormatInt(row.Version, 10)))
	out.Version = row.Version
	out.Table.IsRegisteredWithLakeFormation = new(api.Boolean(false))
	out.Table.IsMultiDialectView = new(api.NullableBoolean(false))
	out.Table.IsMaterializedView = new(api.NullableBoolean(false))
	out.Table.Description = catalogString[api.DescriptionString](row.Description)
	out.Table.Owner = catalogString[api.NameString](row.Owner)
	out.Table.CreatedBy = catalogString[api.NameString](row.CreatedBy)
	out.Table.CreateTime = new(row.CreatedAt.UTC())
	out.Table.UpdateTime = new(row.UpdatedAt.UTC())
	out.Table.LastAccessTime = catalogTime(row.LastAccessAt)
	out.Table.LastAnalyzedTime = catalogTime(row.LastAnalyzedAt)
	out.Table.Retention = catalogInt[api.NonNegativeInteger](row.Retention)
	if err := catalogDecode(row.StorageDescriptorJson, &out.Table.StorageDescriptor); err != nil {
		return out, err
	}
	if err := catalogDecode(row.PartitionKeysJson, &out.Table.PartitionKeys); err != nil {
		return out, err
	}
	if err := catalogDecode(row.ParametersJson, &out.Table.Parameters); err != nil {
		return out, err
	}
	out.Table.TableType = catalogString[api.TableTypeString](row.TableType)
	if err := catalogDecode(row.TargetTableJson, &out.Table.TargetTable); err != nil {
		return out, err
	}
	out.Table.ViewOriginalText = catalogString[api.ViewTextString](row.ViewOriginalText)
	out.Table.ViewExpandedText = catalogString[api.ViewTextString](row.ViewExpandedText)
	return out, nil
}
func (r reader) Table(key domain.TableKey) (domain.TableRecord, error) {
	row, err := r.q.GetGlueTable(r.ctx, sqlcgen.GetGlueTableParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName})
	if err != nil {
		return domain.TableRecord{}, missing(err)
	}
	return decodeTable(row)
}
func (w writer) DeleteTable(key domain.TableKey) error {
	return w.q.DeleteGlueTable(w.ctx, sqlcgen.DeleteGlueTableParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName})
}
func (r reader) Tables(key domain.DatabaseKey) ([]domain.TableRecord, error) {
	rows, err := r.q.ListGlueTables(r.ctx, sqlcgen.ListGlueTablesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.TableRecord, 0, len(rows))
	for _, row := range rows {
		record, err := decodeTable(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func (w writer) PutTable(v domain.TableRecord) error {
	key := v.Key
	p := sqlcgen.PutGlueTableParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName}
	p.CfnOwner = v.CFNOwner
	p.Version = v.Version
	p.Description = catalogNullString(v.Table.Description)
	p.Owner = catalogNullString(v.Table.Owner)
	p.CreatedBy = catalogNullString(v.Table.CreatedBy)
	p.CreatedAt = catalogRequiredTime(v.Table.CreateTime)
	p.UpdatedAt = catalogRequiredTime(v.Table.UpdateTime)
	p.LastAccessAt = catalogNullTime(v.Table.LastAccessTime)
	p.LastAnalyzedAt = catalogNullTime(v.Table.LastAnalyzedTime)
	p.Retention = catalogNullInt(v.Table.Retention)
	{
		encoded, err := catalogEncode(v.Table.StorageDescriptor)
		if err != nil {
			return err
		}
		p.StorageDescriptorJson = encoded
	}
	{
		encoded, err := catalogEncode(v.Table.PartitionKeys)
		if err != nil {
			return err
		}
		p.PartitionKeysJson = encoded
	}
	{
		encoded, err := catalogEncode(v.Table.Parameters)
		if err != nil {
			return err
		}
		p.ParametersJson = encoded
	}
	p.TableType = catalogNullString(v.Table.TableType)
	{
		encoded, err := catalogEncode(v.Table.TargetTable)
		if err != nil {
			return err
		}
		p.TargetTableJson = encoded
	}
	p.ViewOriginalText = catalogNullString(v.Table.ViewOriginalText)
	p.ViewExpandedText = catalogNullString(v.Table.ViewExpandedText)
	return w.q.PutGlueTable(w.ctx, p)
}
func decodeTableVersion(row sqlcgen.GlueTableVersion) (domain.TableVersionRecord, error) {
	out := domain.TableVersionRecord{Key: domain.TableVersionKey{TableKey: domain.TableKey{DatabaseKey: domain.DatabaseKey{CatalogKey: domain.CatalogKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, CatalogID: row.CatalogID}, Name: row.DatabaseName}, TableName: row.TableName}, Version: row.Version}}
	out.Table.Name = new(api.NameString(row.TableName))
	out.Table.DatabaseName = new(api.NameString(row.DatabaseName))
	out.Table.CatalogId = new(api.CatalogIdString(row.CatalogID))
	out.Table.VersionId = new(api.VersionString(strconv.FormatInt(row.Version, 10)))
	out.Table.IsRegisteredWithLakeFormation = new(api.Boolean(false))
	out.Table.IsMultiDialectView = new(api.NullableBoolean(false))
	out.Table.IsMaterializedView = new(api.NullableBoolean(false))
	out.Table.Description = catalogString[api.DescriptionString](row.Description)
	out.Table.Owner = catalogString[api.NameString](row.Owner)
	out.Table.CreatedBy = catalogString[api.NameString](row.CreatedBy)
	out.Table.CreateTime = new(row.CreatedAt.UTC())
	out.Table.UpdateTime = new(row.UpdatedAt.UTC())
	out.Table.LastAccessTime = catalogTime(row.LastAccessAt)
	out.Table.LastAnalyzedTime = catalogTime(row.LastAnalyzedAt)
	out.Table.Retention = catalogInt[api.NonNegativeInteger](row.Retention)
	if err := catalogDecode(row.StorageDescriptorJson, &out.Table.StorageDescriptor); err != nil {
		return out, err
	}
	if err := catalogDecode(row.PartitionKeysJson, &out.Table.PartitionKeys); err != nil {
		return out, err
	}
	if err := catalogDecode(row.ParametersJson, &out.Table.Parameters); err != nil {
		return out, err
	}
	out.Table.TableType = catalogString[api.TableTypeString](row.TableType)
	if err := catalogDecode(row.TargetTableJson, &out.Table.TargetTable); err != nil {
		return out, err
	}
	out.Table.ViewOriginalText = catalogString[api.ViewTextString](row.ViewOriginalText)
	out.Table.ViewExpandedText = catalogString[api.ViewTextString](row.ViewExpandedText)
	return out, nil
}
func (r reader) TableVersion(key domain.TableVersionKey) (domain.TableVersionRecord, error) {
	row, err := r.q.GetGlueTableVersion(r.ctx, sqlcgen.GetGlueTableVersionParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, Version: key.Version})
	if err != nil {
		return domain.TableVersionRecord{}, missing(err)
	}
	return decodeTableVersion(row)
}
func (w writer) DeleteTableVersion(key domain.TableVersionKey) error {
	return w.q.DeleteGlueTableVersion(w.ctx, sqlcgen.DeleteGlueTableVersionParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, Version: key.Version})
}
func (r reader) TableVersions(key domain.TableKey) ([]domain.TableVersionRecord, error) {
	rows, err := r.q.ListGlueTableVersions(r.ctx, sqlcgen.ListGlueTableVersionsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName})
	if err != nil {
		return nil, err
	}
	out := make([]domain.TableVersionRecord, 0, len(rows))
	for _, row := range rows {
		record, err := decodeTableVersion(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func (w writer) PutTableVersion(v domain.TableVersionRecord) error {
	key := v.Key
	p := sqlcgen.PutGlueTableVersionParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, Version: key.Version}
	p.Description = catalogNullString(v.Table.Description)
	p.Owner = catalogNullString(v.Table.Owner)
	p.CreatedBy = catalogNullString(v.Table.CreatedBy)
	p.CreatedAt = catalogRequiredTime(v.Table.CreateTime)
	p.UpdatedAt = catalogRequiredTime(v.Table.UpdateTime)
	p.LastAccessAt = catalogNullTime(v.Table.LastAccessTime)
	p.LastAnalyzedAt = catalogNullTime(v.Table.LastAnalyzedTime)
	p.Retention = catalogNullInt(v.Table.Retention)
	{
		encoded, err := catalogEncode(v.Table.StorageDescriptor)
		if err != nil {
			return err
		}
		p.StorageDescriptorJson = encoded
	}
	{
		encoded, err := catalogEncode(v.Table.PartitionKeys)
		if err != nil {
			return err
		}
		p.PartitionKeysJson = encoded
	}
	{
		encoded, err := catalogEncode(v.Table.Parameters)
		if err != nil {
			return err
		}
		p.ParametersJson = encoded
	}
	p.TableType = catalogNullString(v.Table.TableType)
	{
		encoded, err := catalogEncode(v.Table.TargetTable)
		if err != nil {
			return err
		}
		p.TargetTableJson = encoded
	}
	p.ViewOriginalText = catalogNullString(v.Table.ViewOriginalText)
	p.ViewExpandedText = catalogNullString(v.Table.ViewExpandedText)
	return w.q.PutGlueTableVersion(w.ctx, p)
}
func decodePartition(row sqlcgen.GluePartition) (domain.PartitionRecord, error) {
	out := domain.PartitionRecord{Key: domain.PartitionKey{TableKey: domain.TableKey{DatabaseKey: domain.DatabaseKey{CatalogKey: domain.CatalogKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, CatalogID: row.CatalogID}, Name: row.DatabaseName}, TableName: row.TableName}, Values: row.ValuesJson}}
	out.CFNOwner = row.CfnOwner
	out.Partition.TableName = new(api.NameString(row.TableName))
	out.Partition.DatabaseName = new(api.NameString(row.DatabaseName))
	out.Partition.CatalogId = new(api.CatalogIdString(row.CatalogID))
	if err := catalogDecode(row.ValuesJson, &out.Partition.Values); err != nil {
		return out, err
	}
	out.Partition.CreationTime = new(row.CreatedAt.UTC())
	out.Partition.LastAccessTime = catalogTime(row.LastAccessAt)
	out.Partition.LastAnalyzedTime = catalogTime(row.LastAnalyzedAt)
	if err := catalogDecode(row.ParametersJson, &out.Partition.Parameters); err != nil {
		return out, err
	}
	if err := catalogDecode(row.StorageDescriptorJson, &out.Partition.StorageDescriptor); err != nil {
		return out, err
	}
	return out, nil
}
func (r reader) Partition(key domain.PartitionKey) (domain.PartitionRecord, error) {
	row, err := r.q.GetGluePartition(r.ctx, sqlcgen.GetGluePartitionParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, ValuesJson: key.Values})
	if err != nil {
		return domain.PartitionRecord{}, missing(err)
	}
	return decodePartition(row)
}
func (w writer) DeletePartition(key domain.PartitionKey) error {
	return w.q.DeleteGluePartition(w.ctx, sqlcgen.DeleteGluePartitionParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, ValuesJson: key.Values})
}
func (r reader) Partitions(key domain.TableKey) ([]domain.PartitionRecord, error) {
	rows, err := r.q.ListGluePartitions(r.ctx, sqlcgen.ListGluePartitionsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PartitionRecord, 0, len(rows))
	for _, row := range rows {
		record, err := decodePartition(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func (w writer) PutPartition(v domain.PartitionRecord) error {
	key := v.Key
	p := sqlcgen.PutGluePartitionParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, ValuesJson: key.Values}
	p.CfnOwner = v.CFNOwner
	p.CreatedAt = catalogRequiredTime(v.Partition.CreationTime)
	p.LastAccessAt = catalogNullTime(v.Partition.LastAccessTime)
	p.LastAnalyzedAt = catalogNullTime(v.Partition.LastAnalyzedTime)
	{
		encoded, err := catalogEncode(v.Partition.Parameters)
		if err != nil {
			return err
		}
		p.ParametersJson = encoded
	}
	{
		encoded, err := catalogEncode(v.Partition.StorageDescriptor)
		if err != nil {
			return err
		}
		p.StorageDescriptorJson = encoded
	}
	return w.q.PutGluePartition(w.ctx, p)
}
func decodeFunction(row sqlcgen.GlueFunction) (domain.FunctionRecord, error) {
	out := domain.FunctionRecord{Key: domain.FunctionKey{DatabaseKey: domain.DatabaseKey{CatalogKey: domain.CatalogKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, CatalogID: row.CatalogID}, Name: row.DatabaseName}, FunctionName: row.FunctionName}}
	out.Function.FunctionName = new(api.NameString(row.FunctionName))
	out.Function.DatabaseName = new(api.NameString(row.DatabaseName))
	out.Function.CatalogId = new(api.CatalogIdString(row.CatalogID))
	out.Function.ClassName = catalogString[api.NameString](row.ClassName)
	out.Function.FunctionType = catalogString[api.FunctionType](row.FunctionType)
	out.Function.OwnerName = catalogString[api.NameString](row.OwnerName)
	out.Function.OwnerType = catalogString[api.PrincipalType](row.OwnerType)
	out.Function.CreateTime = new(row.CreatedAt.UTC())
	if err := catalogDecode(row.ResourceUrisJson, &out.Function.ResourceUris); err != nil {
		return out, err
	}
	return out, nil
}
func (r reader) Function(key domain.FunctionKey) (domain.FunctionRecord, error) {
	row, err := r.q.GetGlueFunction(r.ctx, sqlcgen.GetGlueFunctionParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, FunctionName: key.FunctionName})
	if err != nil {
		return domain.FunctionRecord{}, missing(err)
	}
	return decodeFunction(row)
}
func (w writer) DeleteFunction(key domain.FunctionKey) error {
	return w.q.DeleteGlueFunction(w.ctx, sqlcgen.DeleteGlueFunctionParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, FunctionName: key.FunctionName})
}
func (r reader) Functions(key domain.DatabaseKey) ([]domain.FunctionRecord, error) {
	rows, err := r.q.ListGlueFunctions(r.ctx, sqlcgen.ListGlueFunctionsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.FunctionRecord, 0, len(rows))
	for _, row := range rows {
		record, err := decodeFunction(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func (w writer) PutFunction(v domain.FunctionRecord) error {
	key := v.Key
	p := sqlcgen.PutGlueFunctionParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, FunctionName: key.FunctionName}
	p.ClassName = catalogNullString(v.Function.ClassName)
	p.FunctionType = catalogNullString(v.Function.FunctionType)
	p.OwnerName = catalogNullString(v.Function.OwnerName)
	p.OwnerType = catalogNullString(v.Function.OwnerType)
	p.CreatedAt = catalogRequiredTime(v.Function.CreateTime)
	{
		encoded, err := catalogEncode(v.Function.ResourceUris)
		if err != nil {
			return err
		}
		p.ResourceUrisJson = encoded
	}
	return w.q.PutGlueFunction(w.ctx, p)
}
func decodePartitionIndex(row sqlcgen.GluePartitionIndex) (domain.PartitionIndexRecord, error) {
	out := domain.PartitionIndexRecord{Key: domain.PartitionIndexKey{TableKey: domain.TableKey{DatabaseKey: domain.DatabaseKey{CatalogKey: domain.CatalogKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, CatalogID: row.CatalogID}, Name: row.DatabaseName}, TableName: row.TableName}, IndexName: row.IndexName}}
	out.Index.IndexName = new(api.NameString(row.IndexName))
	out.Index.IndexStatus = new(api.PartitionIndexStatus(row.Status))
	if err := catalogDecode(row.KeysJson, &out.Index.Keys); err != nil {
		return out, err
	}
	if err := catalogDecode(row.BackfillErrorsJson, &out.Index.BackfillErrors); err != nil {
		return out, err
	}
	return out, nil
}
func (r reader) PartitionIndex(key domain.PartitionIndexKey) (domain.PartitionIndexRecord, error) {
	row, err := r.q.GetGluePartitionIndex(r.ctx, sqlcgen.GetGluePartitionIndexParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, IndexName: key.IndexName})
	if err != nil {
		return domain.PartitionIndexRecord{}, missing(err)
	}
	return decodePartitionIndex(row)
}
func (w writer) DeletePartitionIndex(key domain.PartitionIndexKey) error {
	return w.q.DeleteGluePartitionIndex(w.ctx, sqlcgen.DeleteGluePartitionIndexParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, IndexName: key.IndexName})
}
func (r reader) PartitionIndexes(key domain.TableKey) ([]domain.PartitionIndexRecord, error) {
	rows, err := r.q.ListGluePartitionIndexes(r.ctx, sqlcgen.ListGluePartitionIndexesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PartitionIndexRecord, 0, len(rows))
	for _, row := range rows {
		record, err := decodePartitionIndex(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func (w writer) PutPartitionIndex(v domain.PartitionIndexRecord) error {
	key := v.Key
	p := sqlcgen.PutGluePartitionIndexParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, IndexName: key.IndexName}
	p.Status = catalogValue(v.Index.IndexStatus)
	{
		encoded, err := catalogEncode(v.Index.Keys)
		if err != nil {
			return err
		}
		p.KeysJson = encoded
	}
	{
		encoded, err := catalogEncode(v.Index.BackfillErrors)
		if err != nil {
			return err
		}
		p.BackfillErrorsJson = encoded
	}
	return w.q.PutGluePartitionIndex(w.ctx, p)
}
func decodeColumnStatistics(row sqlcgen.GlueColumnStatistic) (domain.ColumnStatisticsRecord, error) {
	out := domain.ColumnStatisticsRecord{Key: domain.ColumnStatisticsKey{TableKey: domain.TableKey{DatabaseKey: domain.DatabaseKey{CatalogKey: domain.CatalogKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, CatalogID: row.CatalogID}, Name: row.DatabaseName}, TableName: row.TableName}, ColumnName: row.ColumnName}}
	out.Statistics.ColumnName = new(api.NameString(row.ColumnName))
	out.Statistics.ColumnType = new(api.TypeString(row.ColumnType))
	out.Statistics.AnalyzedTime = new(row.AnalyzedAt.UTC())
	if err := catalogDecode(row.StatisticsDataJson, &out.Statistics.StatisticsData); err != nil {
		return out, err
	}
	return out, nil
}
func (r reader) ColumnStatistics(key domain.ColumnStatisticsKey) (domain.ColumnStatisticsRecord, error) {
	row, err := r.q.GetGlueColumnStatistics(r.ctx, sqlcgen.GetGlueColumnStatisticsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, ColumnName: key.ColumnName})
	if err != nil {
		return domain.ColumnStatisticsRecord{}, missing(err)
	}
	return decodeColumnStatistics(row)
}
func (w writer) DeleteColumnStatistics(key domain.ColumnStatisticsKey) error {
	return w.q.DeleteGlueColumnStatistics(w.ctx, sqlcgen.DeleteGlueColumnStatisticsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, ColumnName: key.ColumnName})
}
func (w writer) PutColumnStatistics(v domain.ColumnStatisticsRecord) error {
	key := v.Key
	p := sqlcgen.PutGlueColumnStatisticsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID, DatabaseName: key.Name, TableName: key.TableName, ColumnName: key.ColumnName}
	p.ColumnType = catalogValue(v.Statistics.ColumnType)
	p.AnalyzedAt = catalogRequiredTime(v.Statistics.AnalyzedTime)
	{
		encoded, err := catalogEncode(v.Statistics.StatisticsData)
		if err != nil {
			return err
		}
		p.StatisticsDataJson = encoded
	}
	return w.q.PutGlueColumnStatistics(w.ctx, p)
}
func decodeResourcePolicy(row sqlcgen.GlueResourcePolicy) (domain.ResourcePolicyRecord, error) {
	out := domain.ResourcePolicyRecord{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}}
	out.Policy.Document = row.Document
	if err := catalogDecode(row.PrincipalIdsJson, &out.Policy.PrincipalIDs); err != nil {
		return out, err
	}
	out.Hash = row.PolicyHash
	out.Created = row.CreatedAt
	out.Updated = row.UpdatedAt
	return out, nil
}
func (r reader) ResourcePolicy(key domain.Scope) (domain.ResourcePolicyRecord, error) {
	row, err := r.q.GetGlueResourcePolicy(r.ctx, sqlcgen.GetGlueResourcePolicyParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region})
	if err != nil {
		return domain.ResourcePolicyRecord{}, missing(err)
	}
	return decodeResourcePolicy(row)
}
func (w writer) DeleteResourcePolicy(key domain.Scope) error {
	return w.q.DeleteGlueResourcePolicy(w.ctx, sqlcgen.DeleteGlueResourcePolicyParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region})
}
func (w writer) PutResourcePolicy(v domain.ResourcePolicyRecord) error {
	key := v.Scope
	p := sqlcgen.PutGlueResourcePolicyParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region}
	p.Document = v.Policy.Document
	{
		encoded, err := catalogEncode(v.Policy.PrincipalIDs)
		if err != nil {
			return err
		}
		p.PrincipalIdsJson = encoded
	}
	p.PolicyHash = v.Hash
	p.CreatedAt = v.Created
	p.UpdatedAt = v.Updated
	return w.q.PutGlueResourcePolicy(w.ctx, p)
}
func decodeCatalogImport(row sqlcgen.GlueCatalogImport) (domain.CatalogImportRecord, error) {
	out := domain.CatalogImportRecord{Key: domain.CatalogKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, CatalogID: row.CatalogID}}
	out.Status.ImportCompleted = new(api.Boolean(row.Completed != 0))
	out.Status.ImportTime = new(row.ImportedAt.UTC())
	out.Status.ImportedBy = new(api.NameString(row.ImportedBy))
	return out, nil
}
func (r reader) CatalogImport(key domain.CatalogKey) (domain.CatalogImportRecord, error) {
	row, err := r.q.GetGlueCatalogImport(r.ctx, sqlcgen.GetGlueCatalogImportParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID})
	if err != nil {
		return domain.CatalogImportRecord{}, missing(err)
	}
	return decodeCatalogImport(row)
}
func (w writer) DeleteCatalogImport(key domain.CatalogKey) error {
	return w.q.DeleteGlueCatalogImport(w.ctx, sqlcgen.DeleteGlueCatalogImportParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID})
}
func (w writer) PutCatalogImport(v domain.CatalogImportRecord) error {
	key := v.Key
	p := sqlcgen.PutGlueCatalogImportParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CatalogID: key.CatalogID}
	p.Completed = catalogBoolean(v.Status.ImportCompleted)
	p.ImportedAt = catalogRequiredTime(v.Status.ImportTime)
	p.ImportedBy = catalogValue(v.Status.ImportedBy)
	return w.q.PutGlueCatalogImport(w.ctx, p)
}
