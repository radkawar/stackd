package glue

import (
	"context"
	"slices"
	"strings"

	api "stackd/internal/awsapi/glue"
	tables "stackd/internal/awsapi/s3tables"
)

func federationInputKey(ctx context.Context, input any) (CatalogKey, DatabaseKey, string, bool) {
	if db, name, ok := catalogInputKeys(ctx, input); ok {
		return db.CatalogKey, db, name, true
	}
	switch in := input.(type) {
	case *api.GetDatabasesInput:
		return catalogKey(ctx, in.CatalogId), DatabaseKey{}, "", true
	case *api.CreateDatabaseInput:
		if in.DatabaseInput != nil {
			db := databaseKey(ctx, in.CatalogId, in.DatabaseInput.Name)
			return db.CatalogKey, db, "", true
		}
	case *api.DeleteDatabaseInput:
		db := databaseKey(ctx, in.CatalogId, in.Name)
		return db.CatalogKey, db, "", true
	}
	return CatalogKey{}, DatabaseKey{}, "", false
}

func (s *Service) routeFederatedCommand(ctx context.Context, tx Reader, action string, input any) (catalogRoute, error) {
	route := catalogRoute{ctx: ctx, input: input}
	key, db, name, selected := federationInputKey(ctx, input)
	if !selected {
		return route, nil
	}
	bucket, mounted, err := s.mountedBucket(ctx, tx, key)
	if err != nil {
		return route, err
	}
	if !mounted {
		// The integration parent cannot acquire a second ordinary Glue namespace.
		parent, err := tx.Catalog(key)
		if err == nil && parent.Catalog.FederatedCatalog != nil {
			if err := s.authorizeCatalog(ctx, tx, action, key); err != nil {
				return route, err
			}
			return route, failure("InvalidInputException", "Select a mounted S3 table bucket child catalog.")
		}
		return route, nil
	}
	if name != "" {
		err = s.authorizeTable(ctx, tx, action, TableKey{DatabaseKey: db, TableName: name})
	} else if db.Name != "" {
		err = s.authorizeDatabase(ctx, tx, action, db)
	} else {
		err = s.authorizeCatalog(ctx, tx, action, key)
	}
	if err != nil {
		return route, err
	}
	arn := new(tables.TableBucketARN(bucket))
	namespace := new(tables.NamespaceName(db.Name))
	tableName := new(tables.TableName(name))
	route.hasOutput = true
	switch in := input.(type) {
	case *api.GetDatabasesInput:
		route.output, err = s.getFederatedDatabases(ctx, tx, key, in)
	case *api.GetDatabaseInput:
		row, rejected := s.s3Tables.GetNamespace(ctx, &tables.GetNamespaceInput{TableBucketARN: arn, Namespace: namespace})
		if rejected != nil {
			return route, federationError(rejected)
		}
		out := federatedDatabase(db)
		out.CreateTime = row.CreatedAt
		route.output = &api.GetDatabaseOutput{Database: &out}
	case *api.CreateDatabaseInput:
		if err := validateFederatedDatabaseInput(in.DatabaseInput); err != nil {
			return route, err
		}
		if len(in.Tags) > 0 {
			return route, unsupported("S3 Tables namespaces do not store Glue resource tags.")
		}
		_, rejected := s.s3Tables.CreateNamespace(ctx, &tables.CreateNamespaceInput{TableBucketARN: arn, Namespace: tables.NamespaceList{tables.NamespaceName(db.Name)}})
		err = federationError(rejected)
		route.output = &api.CreateDatabaseOutput{}
	case *api.UpdateDatabaseInput:
		if in.DatabaseInput == nil || strings.ToLower(value(in.DatabaseInput.Name)) != db.Name {
			return route, failure("InvalidInputException", "An S3 Tables namespace cannot be renamed.")
		}
		if err := validateFederatedDatabaseInput(in.DatabaseInput); err != nil {
			return route, err
		}
		_, rejected := s.s3Tables.GetNamespace(ctx, &tables.GetNamespaceInput{TableBucketARN: arn, Namespace: namespace})
		err = federationError(rejected)
		route.output = &api.UpdateDatabaseOutput{}
	case *api.DeleteDatabaseInput:
		_, rejected := s.s3Tables.DeleteNamespace(ctx, &tables.DeleteNamespaceInput{TableBucketARN: arn, Namespace: namespace})
		err = federationError(rejected)
		route.output = &api.DeleteDatabaseOutput{}
	case *api.GetTablesInput:
		route.output, err = s.getFederatedTables(ctx, tx, db, bucket, in)
	case *api.GetTableInput:
		if in.TransactionId != nil || in.QueryAsOfTime != nil {
			return route, unsupported("S3 Tables does not expose Glue historical or governed table versions.")
		}
		out, loadErr := s.federatedTable(ctx, TableKey{DatabaseKey: db, TableName: name}, bucket)
		if loadErr != nil {
			return route, loadErr
		}
		out, err = projectTable(out, in.AttributesToGet)
		route.output = &api.GetTableOutput{Table: &out}
	case *api.CreateTableInput:
		input, createErr := federatedCreateInput(in, bucket, db)
		if createErr != nil {
			return route, createErr
		}
		publication, ok := ctx.Value(federatedCreateContextKey{}).(*federatedCreatePublication)
		if !ok || !matchesFederatedCreate(publication, key, input) {
			return route, failure("InvalidInputException", "Federated table metadata must be prepared outside the catalog transaction.")
		}
		_, rejected := s.s3Tables.PublishTableCreate(ctx, input, publication.prepared)
		err = federationError(rejected)
		route.output = &api.CreateTableOutput{}
	case *api.UpdateTableInput:
		if err := validateFederatedTableInput(in.TableInput); err != nil {
			return route, err
		}
		if strings.ToLower(value(in.TableInput.Name)) != name {
			return route, unsupported("Use S3 Tables RenameTable to rename an S3 table.")
		}
		if in.TransactionId != nil || in.UpdateOpenTableFormatInput != nil || in.ViewUpdateAction != nil {
			return route, unsupported("Use the S3 Tables metadata-location operation to commit native metadata.")
		}
		if value(in.VersionId) == "" {
			return route, failure("InvalidInputException", "The current S3 Tables version token is required as VersionId.")
		}
		publication, ok := ctx.Value(federatedMetadataContextKey{}).(*federatedMetadataPublication)
		if !ok || publication.catalog != key || value(publication.input.TableBucketARN) != bucket || value(publication.input.Namespace) != db.Name || value(publication.input.Name) != name || value(publication.input.VersionToken) != value(in.VersionId) || value(publication.input.MetadataLocation) != string(in.TableInput.Parameters["metadata_location"]) {
			return route, failure("InvalidInputException", "Federated metadata must be prepared outside the catalog transaction.")
		}
		_, rejected := s.s3Tables.PublishTableMetadataUpdate(ctx, publication.input, publication.prepared)
		err = federationError(rejected)
		route.output = &api.UpdateTableOutput{}
	case *api.DeleteTableInput:
		if in.TransactionId != nil {
			return route, unsupported("S3 Tables does not expose Glue governed transactions.")
		}
		current, rejected := s.s3Tables.GetTableMetadataLocation(ctx, &tables.GetTableMetadataLocationInput{TableBucketARN: arn, Namespace: namespace, Name: tableName})
		if rejected != nil {
			return route, federationError(rejected)
		}
		_, rejected = s.s3Tables.DeleteTable(ctx, &tables.DeleteTableInput{TableBucketARN: arn, Namespace: namespace, Name: tableName, VersionToken: current.VersionToken})
		err = federationError(rejected)
		route.output = &api.DeleteTableOutput{}
	default:
		return route, unsupported("This Glue operation is not supported by the S3 Tables catalog owner.")
	}
	return route, err
}

func validateFederatedDatabaseInput(in *api.DatabaseInput) error {
	if in == nil || value(in.Name) == "" {
		return failure("InvalidInputException", "DatabaseInput.Name is required.")
	}
	if value(in.Description) != "" || value(in.LocationUri) != "" || len(in.Parameters) > 0 || in.TargetDatabase != nil || in.FederatedDatabase != nil {
		return unsupported("S3 Tables namespaces do not store Glue locations, descriptions, parameters or resource links.")
	}
	return nil
}

func validateFederatedTableInput(in *api.TableInput) error {
	if err := validateTableInput(in); err != nil {
		return err
	}
	if !strings.EqualFold(string(in.Parameters["table_type"]), "ICEBERG") || in.Parameters["metadata_location"] == "" || in.TargetTable != nil || len(in.PartitionKeys) > 0 {
		return failure("InvalidInputException", "S3 Tables requires an Iceberg metadata_location and does not accept Hive partitions or resource links.")
	}
	return nil
}

func federatedDatabase(key DatabaseKey) api.Database {
	return api.Database{Name: new(api.NameString(key.Name)), CatalogId: new(api.CatalogIdString(key.CatalogID)), FederatedDatabase: &api.FederatedDatabase{Identifier: new(api.FederationIdentifier(key.Name)), ConnectionName: new(api.NameString("aws:s3tables"))}}
}

func (s *Service) federatedDatabases(ctx context.Context, tx Reader, key CatalogKey, action string) ([]DatabaseRecord, error) {
	bucket, _, err := s.mountedBucket(ctx, tx, key)
	if err != nil {
		return nil, err
	}
	request := &tables.ListNamespacesInput{TableBucketARN: new(tables.TableBucketARN(bucket))}
	var rows []DatabaseRecord
	for {
		page, rejected := s.s3Tables.ListNamespaces(ctx, request)
		if rejected != nil {
			return nil, federationError(rejected)
		}
		for _, namespace := range page.Namespaces {
			if len(namespace.Namespace) != 1 {
				continue
			}
			db := DatabaseKey{CatalogKey: key, Name: string(namespace.Namespace[0])}
			if err := s.authorizeDatabase(ctx, tx, action, db); err != nil {
				if wireError(err).Code == "AccessDeniedException" {
					continue
				}
				return nil, err
			}
			out := federatedDatabase(db)
			out.CreateTime = namespace.CreatedAt
			rows = append(rows, DatabaseRecord{Key: db, Database: out})
		}
		request.ContinuationToken = page.ContinuationToken
		if value(request.ContinuationToken) == "" {
			break
		}
	}
	slices.SortFunc(rows, func(a, b DatabaseRecord) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	return rows, nil
}

func (s *Service) getFederatedDatabases(ctx context.Context, tx Reader, key CatalogKey, in *api.GetDatabasesInput) (*api.GetDatabasesOutput, error) {
	share := value(in.ResourceShareType)
	if share != "" && share != "ALL" && share != "FEDERATED" && share != "FOREIGN" {
		return nil, failure("InvalidInputException", "Invalid ResourceShareType.")
	}
	if len(in.AttributesToGet) > 0 && !slices.Contains(in.AttributesToGet, api.DatabaseAttributesNAME) {
		return nil, failure("InvalidInputException", "AttributesToGet must include NAME.")
	}
	binding := catalogPageBinding("GetDatabases", key.ARN(), share)
	after, err := catalogPageAfter(in.NextToken, binding)
	if err != nil {
		return nil, err
	}
	out := &api.GetDatabasesOutput{DatabaseList: api.DatabaseList{}}
	if share == "FOREIGN" {
		return out, nil
	}
	rows, err := s.federatedDatabases(ctx, tx, key, "GetDatabases")
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Key.Name <= after {
			continue
		}
		if len(out.DatabaseList) == catalogPageSize(in.MaxResults) {
			out.NextToken = catalogNextToken(binding, value(out.DatabaseList[len(out.DatabaseList)-1].Name))
			break
		}
		db := row.Database
		if len(in.AttributesToGet) > 0 {
			db = api.Database{Name: db.Name}
		}
		out.DatabaseList = append(out.DatabaseList, db)
	}
	return out, nil
}

func (s *Service) federatedTable(ctx context.Context, key TableKey, bucket string) (api.Table, error) {
	request := &tables.GetTableInput{TableBucketARN: new(tables.TableBucketARN(bucket)), Namespace: new(tables.NamespaceName(key.Name)), Name: new(tables.TableName(key.TableName))}
	row, rejected := s.s3Tables.GetTable(ctx, request)
	if rejected != nil {
		return api.Table{}, federationError(rejected)
	}
	metadata, rejected := s.s3Tables.GetTableMetadataLocation(ctx, &tables.GetTableMetadataLocationInput{TableBucketARN: request.TableBucketARN, Namespace: request.Namespace, Name: request.Name})
	if rejected != nil {
		return api.Table{}, federationError(rejected)
	}
	parameters := api.ParametersMap{"table_type": "ICEBERG"}
	if value(metadata.MetadataLocation) != "" {
		parameters["metadata_location"] = api.ParametersMapValue(value(metadata.MetadataLocation))
	}
	projection, rejected := s.s3Tables.TableColumns(ctx, bucket, key.Name, key.TableName)
	if rejected != nil {
		return api.Table{}, federationError(rejected)
	}
	columns := make(api.ColumnList, 0, len(projection))
	for _, field := range projection {
		column := api.Column{Name: new(api.NameString(field.Name)), Type: new(api.ColumnTypeString(field.Type))}
		if field.Comment != "" {
			column.Comment = new(api.CommentString(field.Comment))
		}
		columns = append(columns, column)
	}
	return api.Table{Name: new(api.NameString(key.TableName)), DatabaseName: new(api.NameString(key.Name)), CatalogId: new(api.CatalogIdString(key.CatalogID)), TableType: new(api.TableTypeString("EXTERNAL_TABLE")), Parameters: parameters, StorageDescriptor: &api.StorageDescriptor{Location: new(api.LocationString(value(metadata.WarehouseLocation))), Columns: columns}, PartitionKeys: api.ColumnList{}, VersionId: new(api.VersionString(value(metadata.VersionToken))), CreateTime: row.CreatedAt, UpdateTime: row.ModifiedAt}, nil
}

func (s *Service) getFederatedTables(ctx context.Context, tx Reader, db DatabaseKey, bucket string, in *api.GetTablesInput) (*api.GetTablesOutput, error) {
	if in.TransactionId != nil || in.QueryAsOfTime != nil {
		return nil, unsupported("S3 Tables does not expose Glue historical or governed table versions.")
	}
	filter, err := catalogNameFilter(value(in.Expression))
	if err != nil {
		return nil, err
	}
	binding := catalogPageBinding("GetTables", db.ARN(), value(in.Expression))
	after, err := catalogPageAfter(in.NextToken, binding)
	if err != nil {
		return nil, err
	}
	request := &tables.ListTablesInput{TableBucketARN: new(tables.TableBucketARN(bucket)), Namespace: new(tables.NamespaceName(db.Name))}
	var names []string
	for {
		page, rejected := s.s3Tables.ListTables(ctx, request)
		if rejected != nil {
			return nil, federationError(rejected)
		}
		for _, row := range page.Tables {
			names = append(names, value(row.Name))
		}
		request.ContinuationToken = page.ContinuationToken
		if value(request.ContinuationToken) == "" {
			break
		}
	}
	slices.Sort(names)
	out := &api.GetTablesOutput{TableList: api.TableList{}}
	for _, name := range names {
		if name <= after || filter != nil && !filter.MatchString(name) {
			continue
		}
		key := TableKey{DatabaseKey: db, TableName: name}
		if err := s.authorizeTable(ctx, tx, "GetTables", key); err != nil {
			if wireError(err).Code == "AccessDeniedException" {
				continue
			}
			return nil, err
		}
		if len(out.TableList) == catalogPageSize(in.MaxResults) {
			out.NextToken = catalogNextToken(binding, value(out.TableList[len(out.TableList)-1].Name))
			break
		}
		table, err := s.federatedTable(ctx, key, bucket)
		if err != nil {
			if wireError(err).Code == "AccessDeniedException" {
				continue
			}
			return nil, err
		}
		table, err = projectTable(table, in.AttributesToGet)
		if err != nil {
			return nil, err
		}
		out.TableList = append(out.TableList, table)
	}
	return out, nil
}
