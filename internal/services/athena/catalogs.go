package athena

import (
	"context"
	"errors"
	"strings"

	api "stackd/internal/awsapi/athena"
	glueapi "stackd/internal/awsapi/glue"
)

func registerCatalogs(s *Service) {
	registerControl(s, "CreateDataCatalog", s.createDataCatalog)
	registerControl(s, "UpdateDataCatalog", s.updateDataCatalog)
	registerControl(s, "DeleteDataCatalog", s.deleteDataCatalog)
	registerControl(s, "GetDataCatalog", s.getDataCatalog)
	registerControl(s, "ListDataCatalogs", s.listDataCatalogs)
	registerControl(s, "GetDatabase", s.getDatabase)
	registerControl(s, "ListDatabases", s.listDatabases)
	registerControl(s, "GetTableMetadata", s.getTableMetadata)
	registerControl(s, "ListTableMetadata", s.listTableMetadata)
}
func defaultCatalog(key ResourceKey) CatalogRecord {
	return CatalogRecord{Key: key, Data: api.DataCatalog{Name: new(api.CatalogNameString(key.Name)), Type: new(api.DataCatalogType("GLUE")), Parameters: api.ParametersMap{"catalog-id": api.ParametersMapValue(key.AccountID)}}, Tags: map[string]string{}}
}
func validateCatalog(name, kind string, parameters api.ParametersMap) error {
	if name == "" || len(name) > 127 || strings.ContainsAny(name, " /:\t\n") {
		return invalidRequest("Invalid data catalog name.")
	}
	if strings.EqualFold(name, "AwsDataCatalog") {
		return invalidRequest("The default AwsDataCatalog cannot be modified.")
	}
	switch kind {
	case "GLUE":
		if parameters["catalog-id"] == "" {
			return invalidRequest("GLUE data catalogs require catalog-id.")
		}
	case "HIVE":
		if parameters["metadata-function"] == "" {
			return invalidRequest("HIVE data catalogs require metadata-function.")
		}
	case "LAMBDA":
		single := parameters["function"] != ""
		pair := parameters["metadata-function"] != "" && parameters["record-function"] != ""
		if single == pair || single && (parameters["metadata-function"] != "" || parameters["record-function"] != "") {
			return invalidRequest("LAMBDA data catalogs require function or metadata-function and record-function.")
		}
	case "FEDERATED":
		// TODO: Comeback provision the actual CFN/Lambda/Glue connection resources required by FEDERATED registration.
		return unsupported("Automatic federated connector provisioning is unavailable.")
	default:
		return invalidRequest("Invalid data catalog type.")
	}
	return nil
}
func (s *Service) createDataCatalog(ctx context.Context, tx Transaction, in *api.CreateDataCatalogInput) (*api.CreateDataCatalogOutput, error) {
	key := resourceFor(ctx, value(in.Name))
	tags, err := requestTags(in.Tags)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "CreateDataCatalog", key.ARN("datacatalog"), nil, tagConditions(tags)); err != nil {
		return nil, err
	}
	if err := validateCatalog(key.Name, value(in.Type), in.Parameters); err != nil {
		return nil, err
	}
	if _, err := tx.Catalog(key); err == nil {
		return nil, invalidRequest("Data catalog already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	v := CatalogRecord{Key: key, Data: api.DataCatalog{Name: in.Name, Type: in.Type, Description: in.Description, Parameters: in.Parameters}, Tags: tags}
	if err := tx.PutCatalog(v); err != nil {
		return nil, err
	}
	return &api.CreateDataCatalogOutput{}, nil
}
func (s *Service) updateDataCatalog(ctx context.Context, tx Transaction, in *api.UpdateDataCatalogInput) (*api.UpdateDataCatalogOutput, error) {
	v, err := s.loadCatalog(ctx, tx, value(in.Name), "UpdateDataCatalog")
	if err != nil {
		return nil, err
	}
	if err := validateCatalog(v.Key.Name, value(in.Type), in.Parameters); err != nil {
		return nil, err
	}
	v.Data.Type = in.Type
	v.Data.Parameters = in.Parameters
	v.Data.Description = in.Description
	if err := tx.PutCatalog(v); err != nil {
		return nil, err
	}
	return &api.UpdateDataCatalogOutput{}, nil
}
func (s *Service) deleteDataCatalog(ctx context.Context, tx Transaction, in *api.DeleteDataCatalogInput) (*api.DeleteDataCatalogOutput, error) {
	v, err := s.loadCatalog(ctx, tx, value(in.Name), "DeleteDataCatalog")
	if err != nil {
		return nil, err
	}
	if v.Key.Name == "AwsDataCatalog" {
		return nil, invalidRequest("The default AwsDataCatalog cannot be deleted.")
	}
	if err := tx.DeleteCatalog(v.Key); err != nil {
		return nil, err
	}
	return &api.DeleteDataCatalogOutput{}, nil
}
func (s *Service) getDataCatalog(ctx context.Context, tx Transaction, in *api.GetDataCatalogInput) (*api.GetDataCatalogOutput, error) {
	v, err := s.loadCatalog(ctx, tx, value(in.Name), "GetDataCatalog")
	if err != nil {
		return nil, err
	}
	return &api.GetDataCatalogOutput{DataCatalog: &v.Data}, nil
}
func (s *Service) listDataCatalogs(ctx context.Context, tx Transaction, in *api.ListDataCatalogsInput) (*api.ListDataCatalogsOutput, error) {
	if err := s.authorize(ctx, "ListDataCatalogs", "*", nil, nil); err != nil {
		return nil, err
	}
	key := resourceFor(ctx, "AwsDataCatalog")
	if _, err := tx.Catalog(key); errors.Is(err, ErrNotFound) {
		if err := tx.PutCatalog(defaultCatalog(key)); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.MaxResults, 50)
	if err != nil {
		return nil, err
	}
	after, err := cursor(key.Scope, "catalogs", "", in.NextToken)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Catalogs(ResourceQuery{Scope: key.Scope, After: after, Limit: limit + 1})
	if err != nil {
		return nil, err
	}
	out := &api.ListDataCatalogsOutput{DataCatalogsSummary: api.DataCatalogSummaryList{}}
	if len(rows) > limit {
		out.NextToken = nextToken(key.Scope, "catalogs", "", rows[limit-1].Key.Name)
		rows = rows[:limit]
	}
	for _, v := range rows {
		out.DataCatalogsSummary = append(out.DataCatalogsSummary, api.DataCatalogSummary{CatalogName: v.Data.Name, Type: v.Data.Type})
	}
	return out, nil
}
func (s *Service) metadataCatalog(ctx context.Context, tx Transaction, name, action string) (*glueapi.CatalogIdString, error) {
	v, err := s.loadCatalog(ctx, tx, name, action)
	if err != nil {
		return nil, err
	}
	if value(v.Data.Type) != "GLUE" {
		// TODO: Comeback invoke real HIVE/LAMBDA connectors using the federated query SDK protocol.
		return nil, unsupported("This metadata operation requires a Glue data catalog.")
	}
	if s.catalog == nil {
		return nil, unsupported("No Glue catalog adapter is configured.")
	}
	return new(glueapi.CatalogIdString(v.Data.Parameters["catalog-id"])), nil
}
func (s *Service) getDatabase(ctx context.Context, tx Transaction, in *api.GetDatabaseInput) (*api.GetDatabaseOutput, error) {
	id, err := s.metadataCatalog(ctx, tx, value(in.CatalogName), "GetDatabase")
	if err != nil {
		return nil, err
	}
	out, rejected := s.catalog.GetDatabase(ctx, &glueapi.GetDatabaseInput{CatalogId: id, Name: (*glueapi.NameString)(in.DatabaseName)})
	if rejected != nil {
		return nil, rejected
	}
	if out == nil || out.Database == nil {
		return nil, ErrNotFound
	}
	database := databaseView(*out.Database)
	return &api.GetDatabaseOutput{Database: &database}, nil
}
func (s *Service) listDatabases(ctx context.Context, tx Transaction, in *api.ListDatabasesInput) (*api.ListDatabasesOutput, error) {
	id, err := s.metadataCatalog(ctx, tx, value(in.CatalogName), "ListDatabases")
	if err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.MaxResults, 50)
	if err != nil {
		return nil, err
	}
	token, err := cursor(scopeFor(ctx), "databases", value(in.CatalogName), in.NextToken)
	if err != nil {
		return nil, err
	}
	request := &glueapi.GetDatabasesInput{CatalogId: id, MaxResults: new(glueapi.CatalogGetterPageSize(limit))}
	if token != "" {
		request.NextToken = new(glueapi.Token(token))
	}
	rows, rejected := s.catalog.GetDatabases(ctx, request)
	if rejected != nil {
		return nil, rejected
	}
	out := &api.ListDatabasesOutput{DatabaseList: api.DatabaseList{}}
	for _, v := range rows.DatabaseList {
		out.DatabaseList = append(out.DatabaseList, databaseView(v))
	}
	if rows.NextToken != nil {
		out.NextToken = nextToken(scopeFor(ctx), "databases", value(in.CatalogName), value(rows.NextToken))
	}
	return out, nil
}
func (s *Service) getTableMetadata(ctx context.Context, tx Transaction, in *api.GetTableMetadataInput) (*api.GetTableMetadataOutput, error) {
	id, err := s.metadataCatalog(ctx, tx, value(in.CatalogName), "GetTableMetadata")
	if err != nil {
		return nil, err
	}
	out, rejected := s.catalog.GetTable(ctx, &glueapi.GetTableInput{CatalogId: id, DatabaseName: (*glueapi.NameString)(in.DatabaseName), Name: (*glueapi.NameString)(in.TableName)})
	if rejected != nil {
		return nil, rejected
	}
	if out == nil || out.Table == nil {
		return nil, ErrNotFound
	}
	v := tableView(*out.Table)
	return &api.GetTableMetadataOutput{TableMetadata: &v}, nil
}
func (s *Service) listTableMetadata(ctx context.Context, tx Transaction, in *api.ListTableMetadataInput) (*api.ListTableMetadataOutput, error) {
	id, err := s.metadataCatalog(ctx, tx, value(in.CatalogName), "ListTableMetadata")
	if err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.MaxResults, 50)
	if err != nil {
		return nil, err
	}
	parent := value(in.CatalogName) + "/" + value(in.DatabaseName) + "/" + value(in.Expression)
	token, err := cursor(scopeFor(ctx), "tables", parent, in.NextToken)
	if err != nil {
		return nil, err
	}
	request := &glueapi.GetTablesInput{CatalogId: id, DatabaseName: (*glueapi.NameString)(in.DatabaseName), Expression: (*glueapi.FilterString)(in.Expression), MaxResults: new(glueapi.CatalogGetterPageSize(limit))}
	if token != "" {
		request.NextToken = new(glueapi.Token(token))
	}
	rows, rejected := s.catalog.GetTables(ctx, request)
	if rejected != nil {
		return nil, rejected
	}
	out := &api.ListTableMetadataOutput{TableMetadataList: api.TableMetadataList{}}
	for _, v := range rows.TableList {
		out.TableMetadataList = append(out.TableMetadataList, tableView(v))
	}
	if rows.NextToken != nil {
		out.NextToken = nextToken(scopeFor(ctx), "tables", parent, value(rows.NextToken))
	}
	return out, nil
}
func parametersView(in glueapi.ParametersMap) api.ParametersMap {
	if in == nil {
		return nil
	}
	out := make(api.ParametersMap, len(in))
	for k, v := range in {
		out[api.KeyString(k)] = api.ParametersMapValue(v)
	}
	return out
}
func databaseView(in glueapi.Database) api.Database {
	return api.Database{Name: (*api.NameString)(in.Name), Description: (*api.DescriptionString)(in.Description), Parameters: parametersView(in.Parameters)}
}
func columnsView(in glueapi.ColumnList) api.ColumnList {
	out := make(api.ColumnList, len(in))
	for i, v := range in {
		out[i] = api.Column{Name: (*api.NameString)(v.Name), Type: (*api.TypeString)(v.Type), Comment: (*api.CommentString)(v.Comment)}
	}
	return out
}
func tableView(in glueapi.Table) api.TableMetadata {
	v := api.TableMetadata{Name: (*api.NameString)(in.Name), CreateTime: in.CreateTime, LastAccessTime: in.LastAccessTime, TableType: (*api.TableTypeString)(in.TableType), Parameters: parametersView(in.Parameters), PartitionKeys: columnsView(in.PartitionKeys)}
	if in.StorageDescriptor != nil {
		v.Columns = columnsView(in.StorageDescriptor.Columns)
	}
	return v
}
