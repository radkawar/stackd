package integrations

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	native "stackd/engine/athena"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awswire"
)

func hiveInvalid(message string) error {
	return &awswire.Error{Code: "InvalidRequestException", Message: message, StatusCode: 400}
}
func hiveValue[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
func hiveLocation(location string) error {
	value, err := url.Parse(location)
	if err != nil || value.Scheme != "s3" || value.Host == "" || value.User != nil || value.RawQuery != "" || value.Fragment != "" {
		return hiveInvalid("Hive LOCATION must be an s3:// bucket location")
	}
	return nil
}
func hiveColumns(columns []native.DDLColumn) (api.ColumnList, error) {
	out := make(api.ColumnList, 0, len(columns))
	names := map[string]bool{}
	for _, column := range columns {
		name := strings.ToLower(column.Name)
		if name == "" || names[name] || column.Type == "" {
			return nil, hiveInvalid("Column names must be nonempty and unique and have types")
		}
		names[name] = true
		value := api.Column{Name: new(api.NameString(name)), Type: new(api.ColumnTypeString(column.Type))}
		if column.Comment != "" || column.CommentSet {
			value.Comment = new(api.CommentString(column.Comment))
		}
		out = append(out, value)
	}
	return out, nil
}
func hivePartitionValues(keys api.ColumnList, spec map[string]string) (api.ValueStringList, error) {
	if len(keys) == 0 || len(spec) != len(keys) {
		return nil, hiveInvalid("Partition specification must contain every partition column exactly once")
	}
	normalized := make(map[string]string, len(spec))
	for name, value := range spec {
		name = strings.ToLower(name)
		if _, duplicate := normalized[name]; duplicate {
			return nil, hiveInvalid("Partition column specified more than once")
		}
		normalized[name] = value
	}
	values := make(api.ValueStringList, len(keys))
	for i, key := range keys {
		value, ok := normalized[strings.ToLower(hiveValue(key.Name))]
		if !ok {
			return nil, hiveInvalid("Unknown or missing partition column")
		}
		values[i] = api.ValueString(value)
	}
	return values, nil
}
func hivePartitionInput(partition *api.Partition) *api.PartitionInput {
	return &api.PartitionInput{Values: partition.Values, StorageDescriptor: partition.StorageDescriptor, Parameters: partition.Parameters, LastAccessTime: partition.LastAccessTime, LastAnalyzedTime: partition.LastAnalyzedTime}
}

// applyHiveMutation uses the ordinary Glue commands for every read/write. The
// version returned by GetTable fences table metadata replacement; neither
// native effects nor S3 discovery run inside a catalog transaction.
func (a *AthenaEngine) applyHiveMutation(ctx context.Context, catalog AthenaGlue, catalogID, database string, plan native.HiveDDL) error {
	id, db := new(api.CatalogIdString(catalogID)), new(api.NameString(strings.ToLower(database)))
	if plan.Kind == "SET_DATABASE_PROPERTIES" {
		out, rejected := catalog.GetDatabase(ctx, &api.GetDatabaseInput{CatalogId: id, Name: db})
		if rejected != nil {
			return rejected
		}
		old := out.Database
		if old == nil {
			return fmt.Errorf("no database returned by Glue")
		}
		properties := api.CloneParametersMap(old.Parameters)
		if properties == nil {
			properties = api.ParametersMap{}
		}
		for name, value := range plan.Properties {
			properties[api.KeyString(name)] = api.ParametersMapValue(value)
		}
		_, rejected = catalog.command(ctx, "UpdateDatabase", &api.UpdateDatabaseInput{CatalogId: id, Name: db, DatabaseInput: &api.DatabaseInput{Name: old.Name, Description: old.Description, LocationUri: old.LocationUri, Parameters: properties, CreateTableDefaultPermissions: old.CreateTableDefaultPermissions, TargetDatabase: old.TargetDatabase, FederatedDatabase: old.FederatedDatabase}})
		if rejected != nil {
			return rejected
		}
		return nil
	}
	name := new(api.NameString(strings.ToLower(plan.Identifier[len(plan.Identifier)-1])))
	result, rejected := catalog.GetTable(ctx, &api.GetTableInput{CatalogId: id, DatabaseName: db, Name: name})
	if rejected != nil {
		return rejected
	}
	if result.Table == nil || result.Table.StorageDescriptor == nil {
		return hiveInvalid("Hive mutation requires a table storage descriptor")
	}
	table := api.CloneTable(*result.Table)
	if hiveValue(table.TableType) == "VIRTUAL_VIEW" || strings.EqualFold(string(table.Parameters["table_type"]), "ICEBERG") {
		return hiveInvalid("Hive ALTER/MSCK requires a non-Iceberg table, not a view")
	}
	if plan.Kind == "MSCK_REPAIR" {
		return a.repairHivePartitions(ctx, catalog, id, db, name, &table)
	}
	var columnPartition *api.Partition
	if (plan.Kind == "ADD_COLUMNS" || plan.Kind == "REPLACE_COLUMNS") && len(plan.Partitions) > 0 {
		if len(plan.Partitions) != 1 {
			return hiveInvalid("Column mutation requires one partition")
		}
		values, err := hivePartitionValues(table.PartitionKeys, plan.Partitions[0].Values)
		if err != nil {
			return err
		}
		raw, failure := catalog.command(ctx, "GetPartition", &api.GetPartitionInput{CatalogId: id, DatabaseName: db, TableName: name, PartitionValues: values})
		if failure != nil {
			return failure
		}
		output, ok := raw.(*api.GetPartitionOutput)
		if !ok || output.Partition == nil || output.Partition.StorageDescriptor == nil {
			return fmt.Errorf("no partition storage descriptor returned by Glue")
		}
		cloned := api.ClonePartition(*output.Partition)
		columnPartition = &cloned
		table.StorageDescriptor = columnPartition.StorageDescriptor
	}
	switch plan.Kind {
	case "ADD_PARTITIONS", "DROP_PARTITIONS", "RENAME_PARTITION":
		return applyHivePartitions(ctx, catalog, id, db, name, &table, plan)
	case "SET_LOCATION":
		if err := hiveLocation(plan.Location); err != nil {
			return err
		}
		if len(plan.Partitions) > 0 {
			if len(plan.Partitions) != 1 {
				return hiveInvalid("SET LOCATION requires one partition")
			}
			values, err := hivePartitionValues(table.PartitionKeys, plan.Partitions[0].Values)
			if err != nil {
				return err
			}
			raw, failure := catalog.command(ctx, "GetPartition", &api.GetPartitionInput{CatalogId: id, DatabaseName: db, TableName: name, PartitionValues: values})
			if failure != nil {
				return failure
			}
			output, ok := raw.(*api.GetPartitionOutput)
			if !ok || output.Partition == nil || output.Partition.StorageDescriptor == nil {
				return fmt.Errorf("no partition storage descriptor returned by Glue")
			}
			partition := api.ClonePartition(*output.Partition)
			partition.StorageDescriptor.Location = new(api.LocationString(plan.Location))
			_, failure = catalog.command(ctx, "UpdatePartition", &api.UpdatePartitionInput{CatalogId: id, DatabaseName: db, TableName: name, PartitionValueList: api.BoundedPartitionValueList(values), PartitionInput: hivePartitionInput(&partition)})
			if failure != nil {
				return failure
			}
			return nil
		}
		table.StorageDescriptor.Location = new(api.LocationString(plan.Location))
	case "SET_TABLE_PROPERTIES":
		if table.Parameters == nil {
			table.Parameters = api.ParametersMap{}
		}
		for key, value := range plan.Properties {
			table.Parameters[api.KeyString(key)] = api.ParametersMapValue(value)
		}
	case "ADD_COLUMNS", "REPLACE_COLUMNS":
		columns, err := hiveColumns(plan.Columns)
		if err != nil {
			return err
		}
		if plan.Kind == "REPLACE_COLUMNS" {
			if table.StorageDescriptor.SerdeInfo == nil || hiveValue(table.StorageDescriptor.SerdeInfo.SerializationLibrary) != "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe" {
				return hiveInvalid("REPLACE COLUMNS requires LazySimpleSerDe")
			}
		}
		for _, column := range columns {
			if hiveValue(column.Type) == "date" {
				return hiveInvalid("ADD/REPLACE COLUMNS does not support date columns")
			}
		}
		names := map[string]bool{}
		for _, key := range table.PartitionKeys {
			names[hiveValue(key.Name)] = true
		}
		if plan.Kind == "ADD_COLUMNS" {
			for _, column := range table.StorageDescriptor.Columns {
				names[hiveValue(column.Name)] = true
			}
		}
		for _, column := range columns {
			if names[hiveValue(column.Name)] {
				return hiveInvalid("Column already exists or duplicates a partition key")
			}
			names[hiveValue(column.Name)] = true
		}
		if plan.Kind == "REPLACE_COLUMNS" {
			table.StorageDescriptor.Columns = columns
		} else {
			table.StorageDescriptor.Columns = append(table.StorageDescriptor.Columns, columns...)
		}
	case "CHANGE_COLUMN":
		columns, err := hiveColumns(plan.Columns)
		if err != nil {
			return err
		}
		if len(columns) != 1 {
			return hiveInvalid("CHANGE requires one column")
		}
		position := -1
		for i, column := range table.StorageDescriptor.Columns {
			if strings.EqualFold(hiveValue(column.Name), plan.OldColumn) {
				position = i
			}
			if strings.EqualFold(hiveValue(column.Name), hiveValue(columns[0].Name)) && !strings.EqualFold(hiveValue(column.Name), plan.OldColumn) {
				return hiveInvalid("Renamed column already exists")
			}
		}
		if position < 0 {
			return hiveInvalid("Column to change does not exist")
		}
		for _, key := range table.PartitionKeys {
			if strings.EqualFold(hiveValue(key.Name), hiveValue(columns[0].Name)) {
				return hiveInvalid("Column duplicates a partition key")
			}
		}
		// COMMENT is optional; absence preserves the existing comment.
		if columns[0].Comment == nil {
			columns[0].Comment = table.StorageDescriptor.Columns[position].Comment
		}
		remaining := append(table.StorageDescriptor.Columns[:position:position], table.StorageDescriptor.Columns[position+1:]...)
		target := position
		if plan.First {
			target = 0
		} else if plan.AfterColumn != "" {
			target = -1
			for i, column := range remaining {
				if strings.EqualFold(hiveValue(column.Name), plan.AfterColumn) {
					target = i + 1
				}
			}
			if target < 0 {
				return hiveInvalid("AFTER column does not exist")
			}
		}
		remaining = append(remaining, api.Column{})
		copy(remaining[target+1:], remaining[target:])
		remaining[target] = columns[0]
		table.StorageDescriptor.Columns = remaining
	default:
		return fmt.Errorf("unsupported native Hive mutation %q", plan.Kind)
	}
	if columnPartition != nil {
		columnPartition.StorageDescriptor = table.StorageDescriptor
		_, rejected = catalog.command(ctx, "UpdatePartition", &api.UpdatePartitionInput{CatalogId: id, DatabaseName: db, TableName: name, PartitionValueList: api.BoundedPartitionValueList(columnPartition.Values), PartitionInput: hivePartitionInput(columnPartition)})
		if rejected != nil {
			return rejected
		}
		return nil
	}
	input := &api.TableInput{Name: table.Name, Description: table.Description, Owner: table.Owner, LastAccessTime: table.LastAccessTime, LastAnalyzedTime: table.LastAnalyzedTime, Retention: table.Retention, StorageDescriptor: table.StorageDescriptor, PartitionKeys: table.PartitionKeys, Parameters: table.Parameters, TableType: table.TableType, ViewOriginalText: table.ViewOriginalText, ViewExpandedText: table.ViewExpandedText, TargetTable: table.TargetTable}
	_, rejected = catalog.command(ctx, "UpdateTable", &api.UpdateTableInput{CatalogId: id, DatabaseName: db, TableInput: input, VersionId: table.VersionId})
	if rejected != nil {
		return rejected
	}
	return nil
}

func applyHivePartitions(ctx context.Context, catalog AthenaGlue, id *api.CatalogIdString, db, name *api.NameString, table *api.Table, plan native.HiveDDL) error {
	for _, spec := range plan.Partitions {
		values, err := hivePartitionValues(table.PartitionKeys, spec.Values)
		if err != nil {
			return err
		}
		switch plan.Kind {
		case "ADD_PARTITIONS":
			location := spec.Location
			if location == "" {
				location = strings.TrimRight(hiveValue(table.StorageDescriptor.Location), "/") + "/"
				for i, key := range table.PartitionKeys {
					location += hiveEscapePartition(hiveValue(key.Name)) + "=" + hiveEscapePartition(string(values[i])) + "/"
				}
			}
			if err := hiveLocation(location); err != nil {
				return err
			}
			storage := api.CloneStorageDescriptor(*table.StorageDescriptor)
			storage.Location = new(api.LocationString(location))
			// BatchCreatePartition is the same current authorization edge used by MSCK.
			raw, rejected := catalog.command(ctx, "BatchCreatePartition", &api.BatchCreatePartitionInput{CatalogId: id, DatabaseName: db, TableName: name, PartitionInputList: api.PartitionInputList{{Values: values, StorageDescriptor: &storage}}})
			if rejected != nil {
				return rejected
			}
			output, ok := raw.(*api.BatchCreatePartitionOutput)
			if !ok {
				return fmt.Errorf("unexpected partition response from Glue")
			}
			for _, failure := range output.Errors {
				if failure.ErrorDetail != nil && !(plan.IfNotExists && hiveValue(failure.ErrorDetail.ErrorCode) == "AlreadyExistsException") {
					return hiveInvalid(hiveValue(failure.ErrorDetail.ErrorMessage))
				}
			}
		case "DROP_PARTITIONS":
			_, rejected := catalog.command(ctx, "DeletePartition", &api.DeletePartitionInput{CatalogId: id, DatabaseName: db, TableName: name, PartitionValues: values})
			if rejected != nil && !(plan.IfExists && rejected.Code == "EntityNotFoundException") {
				return rejected
			}
		case "RENAME_PARTITION":
			replacement, err := hivePartitionValues(table.PartitionKeys, plan.NewPartition)
			if err != nil {
				return err
			}
			raw, rejected := catalog.command(ctx, "GetPartition", &api.GetPartitionInput{CatalogId: id, DatabaseName: db, TableName: name, PartitionValues: values})
			if rejected != nil {
				return rejected
			}
			output, ok := raw.(*api.GetPartitionOutput)
			if !ok || output.Partition == nil {
				return fmt.Errorf("no partition returned by Glue")
			}
			partition := api.ClonePartition(*output.Partition)
			partition.Values = replacement
			_, rejected = catalog.command(ctx, "UpdatePartition", &api.UpdatePartitionInput{CatalogId: id, DatabaseName: db, TableName: name, PartitionValueList: api.BoundedPartitionValueList(values), PartitionInput: hivePartitionInput(&partition)})
			if rejected != nil {
				return rejected
			}
		}
	}
	return nil
}

// Hive's FileUtils.escapePathName escapes only this fixed set, not all URI
// punctuation. Keep existing on-disk Hive partition layout interoperable.
func hiveEscapePartition(value string) string {
	if value == "" {
		return "__HIVE_DEFAULT_PARTITION__"
	}
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	for i := range len(value) {
		b := value[i]
		if b < 32 || b == 127 || strings.ContainsRune("\"#%'*/:=?\\{[]^", rune(b)) {
			out.WriteByte('%')
			out.WriteByte(hex[b>>4])
			out.WriteByte(hex[b&15])
		} else {
			out.WriteByte(b)
		}
	}
	return out.String()
}
