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
	qualifiedCatalog := catalogName
	namespace := plan.Kind == "CREATE_DATABASE" || plan.Kind == "DROP_DATABASE" || plan.Kind == "SET_DATABASE_PROPERTIES"
	if (namespace && len(plan.Identifier) == 2) || (!namespace && len(plan.Identifier) == 3) {
		qualifiedCatalog = plan.Identifier[0]
	}
	resolver := native.Request{AccountID: query.Key.AccountID, Catalog: strings.ToLower(catalogName), CatalogID: catalogID}
	if request.Catalogs != nil {
		resolver.Catalogs = make([]native.CatalogRegistration, 0, len(request.Catalogs))
		for _, registration := range request.Catalogs {
			if registration.Name != nil && registration.Type != nil {
				resolver.Catalogs = append(resolver.Catalogs, native.CatalogRegistration{Name: string(*registration.Name), Kind: string(*registration.Type), CatalogID: string(registration.Parameters["catalog-id"])})
			}
		}
	}
	var resolveErr error
	catalogID, resolveErr = resolver.CatalogIDFor(qualifiedCatalog)
	if resolveErr != nil {
		return resolveErr
	}
	if request.AuthorizeCatalog != nil {
		if err := request.AuthorizeCatalog(ctx, qualifiedCatalog, catalogID); err != nil {
			return err
		}
	}
	var properties api.ParametersMap
	if plan.Kind != "DROP_DATABASE" {
		properties = make(api.ParametersMap, len(plan.Properties))
		for name, value := range plan.Properties {
			properties[api.KeyString(name)] = api.ParametersMapValue(value)
		}
	}
	switch plan.Kind {
	case "CREATE_DATABASE", "DROP_DATABASE", "SET_DATABASE_PROPERTIES":
		if len(plan.Identifier) > 2 {
			return fmt.Errorf("hive database identifier has too many components")
		}
		name := strings.ToLower(plan.Identifier[len(plan.Identifier)-1])
		if plan.Kind == "SET_DATABASE_PROPERTIES" {
			return a.applyHiveMutation(ctx, catalog, catalogID, name, plan)
		}
		if plan.Kind == "DROP_DATABASE" {
			_, rejected := a.Glue.DropHiveDatabase(awsctx.WithViaService(ctx, "athena.amazonaws.com"), &api.DeleteDatabaseInput{CatalogId: new(api.CatalogIdString(catalogID)), Name: new(api.NameString(name))}, plan.Cascade)
			if rejected != nil && !(plan.IfExists && rejected.Code == "EntityNotFoundException") {
				return rejected
			}
			return nil
		}
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
		if plan.BucketCount != 0 || len(plan.BucketColumns) != 0 {
			if plan.BucketCount < 1 || len(plan.BucketColumns) == 0 {
				return hiveInvalid("CLUSTERED BY requires columns and a positive bucket count")
			}
			input.StorageDescriptor.NumberOfBuckets = new(api.Integer(plan.BucketCount))
			for _, name := range plan.BucketColumns {
				input.StorageDescriptor.BucketColumns = append(input.StorageDescriptor.BucketColumns, api.NameString(strings.ToLower(name)))
			}
			input.Parameters[api.KeyString("bucketing_version")] = api.ParametersMapValue("1")
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
		if plan.BucketCount > 0 {
			for _, name := range plan.BucketColumns {
				found := false
				for _, column := range input.StorageDescriptor.Columns {
					if strings.EqualFold(hiveValue(column.Name), name) {
						found = true
					}
				}
				if !found {
					return hiveInvalid("Bucket columns must be existing non-partition columns")
				}
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
		if len(plan.Identifier) > 3 {
			return hiveInvalid("Hive table identifier has too many components")
		}
		if len(plan.Identifier) > 1 {
			database = plan.Identifier[len(plan.Identifier)-2]
		}
		return a.applyHiveMutation(ctx, catalog, catalogID, database, plan)
	}
}
