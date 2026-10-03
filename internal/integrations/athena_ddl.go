package integrations

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	native "stackd/engine/athena"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/athena"
)

func (a *AthenaEngine) applyHiveDDL(ctx context.Context, request athena.ExecutionRequest, plan native.HiveDDL) error {
	query := request.Query
	metadata := awsctx.Clone(query.Caller)
	metadata.ParentEventID, metadata.InvokedBy = query.ParentEventID, "athena.amazonaws.com"
	ctx = awsctx.WithMetadata(ctx, metadata)
	catalogID, catalogName, database := query.Key.AccountID, "AwsDataCatalog", "default"
	if value, ok := request.Catalog.Parameters["catalog-id"]; ok {
		catalogID = string(value)
	}
	if execution := query.Data.QueryExecutionContext; execution != nil {
		if execution.Catalog != nil {
			catalogName = string(*execution.Catalog)
		}
		if execution.Database != nil {
			database = string(*execution.Database)
		}
	}
	catalog := AthenaGlue{Glue: a.Glue}
	if len(plan.Identifier) == 0 {
		return fmt.Errorf("native Hive DDL has no identifier")
	}
	properties := make(api.ParametersMap, len(plan.Properties))
	for name, value := range plan.Properties {
		properties[api.KeyString(name)] = api.ParametersMapValue(value)
	}
	switch plan.Kind {
	case "CREATE_DATABASE":
		if len(plan.Identifier) > 2 {
			return fmt.Errorf("hive database identifier has too many components")
		}
		if len(plan.Identifier) == 2 {
			if strings.EqualFold(plan.Identifier[0], "AwsDataCatalog") {
				catalogID = query.Key.AccountID
			} else if !strings.EqualFold(plan.Identifier[0], catalogName) {
				return fmt.Errorf("hive DDL references an unconfigured Athena catalog")
			}
		}
		name := strings.ToLower(plan.Identifier[len(plan.Identifier)-1])
		input := &api.DatabaseInput{Name: new(api.NameString(name)), Parameters: properties}
		if plan.Comment != "" {
			input.Description = new(api.DescriptionString(plan.Comment))
		}
		if plan.Location != "" {
			input.LocationUri = new(api.URI(plan.Location))
		}
		_, rejected := catalog.command(ctx, "CreateDatabase", &api.CreateDatabaseInput{CatalogId: new(api.CatalogIdString(catalogID)), DatabaseInput: input})
		if rejected != nil && !(plan.IfNotExists && rejected.Code == "AlreadyExistsException") {
			return rejected
		}
		return nil
	case "CREATE_TABLE":
		if !plan.External {
			return &awswire.Error{Code: "InvalidRequestException", Message: "Non-Iceberg Hive tables require CREATE EXTERNAL TABLE", StatusCode: 400}
		}
		if len(plan.Identifier) > 3 {
			return fmt.Errorf("hive table identifier has too many components")
		}
		if len(plan.Identifier) > 1 {
			database = plan.Identifier[len(plan.Identifier)-2]
		}
		if len(plan.Identifier) == 3 {
			if strings.EqualFold(plan.Identifier[0], "AwsDataCatalog") {
				catalogID = query.Key.AccountID
			} else if !strings.EqualFold(plan.Identifier[0], catalogName) {
				return fmt.Errorf("hive DDL references an unconfigured Athena catalog")
			}
		}
		location, err := url.Parse(plan.Location)
		if err != nil || location.Scheme != "s3" || location.Host == "" || location.User != nil || location.RawQuery != "" || location.Fragment != "" {
			return &awswire.Error{Code: "InvalidRequestException", Message: "External tables require an S3 LOCATION", StatusCode: 400}
		}
		input := &api.TableInput{Name: new(api.NameString(strings.ToLower(plan.Identifier[len(plan.Identifier)-1]))), TableType: new(api.TableTypeString("EXTERNAL_TABLE")), Parameters: properties, PartitionKeys: api.ColumnList{}, StorageDescriptor: &api.StorageDescriptor{Location: new(api.LocationString(plan.Location)), InputFormat: new(api.FormatString(plan.InputFormat)), OutputFormat: new(api.FormatString(plan.OutputFormat)), SerdeInfo: &api.SerDeInfo{SerializationLibrary: new(api.NameString(plan.Serde)), Parameters: api.ParametersMap{}}}}
		if plan.Comment != "" {
			input.Description = new(api.DescriptionString(plan.Comment))
			input.Parameters[api.KeyString("comment")] = api.ParametersMapValue(plan.Comment)
		}
		input.Parameters[api.KeyString("EXTERNAL")] = api.ParametersMapValue("TRUE")
		for name, value := range plan.SerdeProperties {
			input.StorageDescriptor.SerdeInfo.Parameters[api.KeyString(name)] = api.ParametersMapValue(value)
		}
		partitionNames := make(map[string]bool, len(plan.PartitionColumns))
		for _, name := range plan.PartitionColumns {
			partitionNames[name] = true
		}
		for _, column := range plan.Columns {
			value := api.Column{Name: new(api.NameString(strings.ToLower(column.Name))), Type: new(api.ColumnTypeString(column.Type))}
			if column.Comment != "" {
				value.Comment = new(api.CommentString(column.Comment))
			}
			if partitionNames[column.Name] {
				input.PartitionKeys = append(input.PartitionKeys, value)
			} else {
				input.StorageDescriptor.Columns = append(input.StorageDescriptor.Columns, value)
			}
		}
		if strings.EqualFold(plan.Properties["table_type"], "DELTA") {
			// Delta's transaction log and Parquet bytes remain native-owned;
			// Glue stores only the registered table's location and schema.
			input.Parameters[api.KeyString("spark.sql.sources.provider")] = api.ParametersMapValue("delta")
			input.Parameters[api.KeyString("classification")] = api.ParametersMapValue("delta")
		}
		_, rejected := catalog.command(ctx, "CreateTable", &api.CreateTableInput{CatalogId: new(api.CatalogIdString(catalogID)), DatabaseName: new(api.NameString(strings.ToLower(database))), TableInput: input})
		if rejected != nil && !(plan.IfNotExists && rejected.Code == "AlreadyExistsException") {
			return rejected
		}
		return nil
	default:
		return fmt.Errorf("unsupported native Hive DDL plan %q", plan.Kind)
	}
}
