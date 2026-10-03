package glue

import (
	"context"
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/glue"
)

func (s *Service) requireCatalog(r Reader, key CatalogKey) error {
	if key.CatalogID == key.AccountID {
		return nil
	}
	_, err := r.Catalog(key)
	return err
}
func rootCatalog(key CatalogKey) CatalogRecord {
	return CatalogRecord{Key: key, Catalog: api.Catalog{Name: new(api.CatalogNameString(key.AccountID)), CatalogId: new(api.CatalogIdString(key.CatalogID)), ResourceArn: new(api.ResourceArnString(key.ARN()))}}
}
func (s *Service) createCatalog(ctx context.Context, tx Transaction, in *api.CreateCatalogInput) (*api.CreateCatalogOutput, error) {
	scope := scopeFor(ctx)
	name := strings.ToLower(value(in.Name))
	key := CatalogKey{Scope: scope, CatalogID: scope.AccountID + ":" + name}
	tags := catalogTags(in.Tags)
	if err := s.authorizeCatalogCreate(ctx, tx, "CreateCatalog", key, key.ARN(), tags); err != nil {
		return nil, err
	}
	if _, err := tx.Catalog(key); err == nil {
		return nil, failure("AlreadyExistsException", "Catalog already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	input := in.CatalogInput
	if input == nil {
		return nil, failure("InvalidInputException", "CatalogInput is required.")
	}
	// TODO: Comeback federated catalog and managed Redshift catalog provisioning require their actual owners.
	if input.FederatedCatalog != nil || input.TargetRedshiftCatalog != nil || input.CatalogProperties != nil {
		return nil, unsupported("Federated and managed catalog provisioning is not available.")
	}
	now := s.clock.Now().UTC()
	record := CatalogRecord{Key: key, Tags: tags, Catalog: api.Catalog{Name: new(api.CatalogNameString(name)), CatalogId: new(api.CatalogIdString(key.CatalogID)), ResourceArn: new(api.ResourceArnString(key.ARN())), Description: input.Description, Parameters: input.Parameters, CreateDatabaseDefaultPermissions: input.CreateDatabaseDefaultPermissions, CreateTableDefaultPermissions: input.CreateTableDefaultPermissions, AllowFullTableExternalDataAccess: input.AllowFullTableExternalDataAccess, CreateTime: &now, UpdateTime: &now}}
	return &api.CreateCatalogOutput{}, tx.PutCatalog(record)
}
func (s *Service) getCatalog(ctx context.Context, tx Transaction, in *api.GetCatalogInput) (*api.GetCatalogOutput, error) {
	key := catalogKey(ctx, in.CatalogId)
	if err := s.authorizeCatalog(ctx, tx, "GetCatalog", key); err != nil {
		return nil, err
	}
	record := rootCatalog(key)
	if key.CatalogID != key.AccountID {
		var err error
		record, err = tx.Catalog(key)
		if err != nil {
			return nil, err
		}
	}
	return &api.GetCatalogOutput{Catalog: &record.Catalog}, nil
}
func (s *Service) getCatalogs(ctx context.Context, tx Transaction, in *api.GetCatalogsInput) (*api.GetCatalogsOutput, error) {
	key := catalogKey(ctx, in.ParentCatalogId)
	if err := s.authorizeCatalog(ctx, tx, "GetCatalogs", key); err != nil {
		return nil, err
	}
	if err := s.requireCatalog(tx, key); err != nil {
		return nil, err
	}
	rows, err := tx.Catalogs(key.Scope)
	if err != nil {
		return nil, err
	}
	if in.IncludeRoot != nil && bool(*in.IncludeRoot) && key.CatalogID == key.AccountID {
		rows = append([]CatalogRecord{rootCatalog(key)}, rows...)
	}
	binding := catalogPageBinding("GetCatalogs", key.ARN())
	after, err := catalogPageAfter(in.NextToken, binding)
	if err != nil {
		return nil, err
	}
	limit := catalogPageSize(in.MaxResults)
	out := &api.GetCatalogsOutput{CatalogList: api.CatalogList{}}
	for _, row := range rows {
		if row.Key.CatalogID <= after {
			continue
		}
		remainder := strings.TrimPrefix(row.Key.CatalogID, key.CatalogID+":")
		if row.Key.CatalogID != key.CatalogID && remainder == row.Key.CatalogID {
			continue
		}
		if (in.Recursive == nil || !bool(*in.Recursive)) && strings.Contains(remainder, ":") {
			continue
		}
		if err := s.authorizeCatalog(ctx, tx, "GetCatalogs", row.Key); err != nil {
			if wireError(err).Code == "AccessDeniedException" {
				continue
			}
			return nil, err
		}
		if in.HasDatabases != nil {
			dbs, err := tx.Databases(row.Key)
			if err != nil {
				return nil, err
			}
			if (len(dbs) > 0) != bool(*in.HasDatabases) {
				continue
			}
		}
		if len(out.CatalogList) == limit {
			out.NextToken = catalogNextToken(binding, value(out.CatalogList[len(out.CatalogList)-1].CatalogId))
			break
		}
		out.CatalogList = append(out.CatalogList, row.Catalog)
	}
	return out, nil
}
func (s *Service) deleteCatalog(ctx context.Context, tx Transaction, in *api.DeleteCatalogInput) (*api.DeleteCatalogOutput, error) {
	key := catalogKey(ctx, in.CatalogId)
	if err := s.authorizeCatalog(ctx, tx, "DeleteCatalog", key); err != nil {
		return nil, err
	}
	if key.CatalogID == key.AccountID {
		return nil, failure("InvalidInputException", "The root Data Catalog cannot be deleted.")
	}
	if _, err := tx.Catalog(key); err != nil {
		return nil, err
	}
	dbs, err := tx.Databases(key)
	if err != nil {
		return nil, err
	}
	for _, db := range dbs {
		if err := s.deleteDatabaseRecord(ctx, tx, "DeleteCatalog", db.Key); err != nil {
			return nil, err
		}
	}
	return &api.DeleteCatalogOutput{}, tx.DeleteCatalog(key)
}

func databaseDescription(key DatabaseKey, input *api.DatabaseInput) api.Database {
	return api.Database{Name: new(api.NameString(key.Name)), CatalogId: new(api.CatalogIdString(key.CatalogID)), Description: input.Description, LocationUri: input.LocationUri, Parameters: input.Parameters, CreateTableDefaultPermissions: input.CreateTableDefaultPermissions, TargetDatabase: input.TargetDatabase, FederatedDatabase: input.FederatedDatabase}
}
func (s *Service) createDatabase(ctx context.Context, tx Transaction, in *api.CreateDatabaseInput) (*api.CreateDatabaseOutput, error) {
	if in.DatabaseInput == nil {
		return nil, failure("InvalidInputException", "DatabaseInput is required.")
	}
	key := databaseKey(ctx, in.CatalogId, in.DatabaseInput.Name)
	tags := catalogTags(in.Tags)
	if err := s.authorizeCatalogCreate(ctx, tx, "CreateDatabase", key.CatalogKey, key.ARN(), tags); err != nil {
		return nil, err
	}
	if err := s.requireCatalog(tx, key.CatalogKey); err != nil {
		return nil, err
	}
	if _, err := tx.Database(key); err == nil {
		return nil, failure("AlreadyExistsException", "Database already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	// TODO: Comeback resolve federated databases through the selected external catalog owner.
	if in.DatabaseInput.FederatedDatabase != nil {
		return nil, unsupported("Federated databases require an external catalog connection.")
	}
	if in.DatabaseInput.TargetDatabase != nil {
		if _, err := databaseLinkKey(key, in.DatabaseInput.TargetDatabase); err != nil {
			return nil, err
		}
	}
	record := DatabaseRecord{Key: key, Database: databaseDescription(key, in.DatabaseInput), Tags: tags}
	record.Database.CreateTime = new(s.clock.Now().UTC())
	return &api.CreateDatabaseOutput{}, tx.PutDatabase(record)
}
func (s *Service) getDatabase(ctx context.Context, tx Transaction, in *api.GetDatabaseInput) (*api.GetDatabaseOutput, error) {
	key := databaseKey(ctx, in.CatalogId, in.Name)
	if err := s.authorizeDatabase(ctx, tx, "GetDatabase", key); err != nil {
		return nil, err
	}
	record, err := tx.Database(key)
	if err != nil {
		return nil, err
	}
	return &api.GetDatabaseOutput{Database: &record.Database}, nil
}
func (s *Service) getDatabases(ctx context.Context, tx Transaction, in *api.GetDatabasesInput) (*api.GetDatabasesOutput, error) {
	key := catalogKey(ctx, in.CatalogId)
	if err := s.authorizeCatalog(ctx, tx, "GetDatabases", key); err != nil {
		return nil, err
	}
	if err := s.requireCatalog(tx, key); err != nil {
		return nil, err
	}
	share := value(in.ResourceShareType)
	if share != "" && share != "FOREIGN" && share != "ALL" && share != "FEDERATED" {
		return nil, failure("InvalidInputException", "Invalid ResourceShareType.")
	}
	if len(in.AttributesToGet) > 0 && !slices.Contains(in.AttributesToGet, api.DatabaseAttributesNAME) {
		return nil, failure("InvalidInputException", "AttributesToGet must include NAME.")
	}
	rows, err := tx.Databases(key)
	if err != nil {
		return nil, err
	}
	if share == "FOREIGN" {
		rows = nil
	}
	if share == "ALL" || share == "FOREIGN" {
		foreign, err := tx.ForeignDatabases(key.Scope)
		if err != nil {
			return nil, err
		}
		rows = append(rows, foreign...)
	}
	slices.SortFunc(rows, func(a, b DatabaseRecord) int {
		if n := strings.Compare(a.Key.Name, b.Key.Name); n != 0 {
			return n
		}
		return strings.Compare(a.Key.CatalogID, b.Key.CatalogID)
	})
	binding := catalogPageBinding("GetDatabases", key.ARN(), share)
	after, err := catalogPageAfter(in.NextToken, binding)
	if err != nil {
		return nil, err
	}
	limit := catalogPageSize(in.MaxResults)
	out := &api.GetDatabasesOutput{DatabaseList: api.DatabaseList{}}
	last := ""
	for _, row := range rows {
		cursor := row.Key.Name + "\x00" + row.Key.CatalogID
		if cursor <= after {
			continue
		}
		if share == "FEDERATED" && row.Database.FederatedDatabase == nil {
			continue
		}
		if err := s.authorizeDatabase(ctx, tx, "GetDatabases", row.Key); err != nil {
			if wireError(err).Code == "AccessDeniedException" {
				continue
			}
			return nil, err
		}
		if len(out.DatabaseList) == limit {
			out.NextToken = catalogNextToken(binding, last)
			break
		}
		v := row.Database
		if len(in.AttributesToGet) > 0 {
			v = api.Database{Name: v.Name}
			if slices.Contains(in.AttributesToGet, api.DatabaseAttributesTARGET_DATABASE) {
				v.TargetDatabase = row.Database.TargetDatabase
			}
		}
		out.DatabaseList = append(out.DatabaseList, v)
		last = cursor
	}
	return out, nil
}
func (s *Service) updateDatabase(ctx context.Context, tx Transaction, in *api.UpdateDatabaseInput) (*api.UpdateDatabaseOutput, error) {
	key := databaseKey(ctx, in.CatalogId, in.Name)
	if err := s.authorizeDatabase(ctx, tx, "UpdateDatabase", key); err != nil {
		return nil, err
	}
	record, err := tx.Database(key)
	if err != nil {
		return nil, err
	}
	if in.DatabaseInput == nil || strings.ToLower(value(in.DatabaseInput.Name)) != key.Name {
		return nil, failure("InvalidInputException", "Database name cannot be changed.")
	}
	if in.DatabaseInput.FederatedDatabase != nil {
		return nil, unsupported("Federated database updates require an external catalog connection.")
	}
	updated := databaseDescription(key, in.DatabaseInput)
	updated.CreateTime = record.Database.CreateTime
	record.Database = updated
	return &api.UpdateDatabaseOutput{}, tx.PutDatabase(record)
}
func (s *Service) deleteDatabase(ctx context.Context, tx Transaction, in *api.DeleteDatabaseInput) (*api.DeleteDatabaseOutput, error) {
	key := databaseKey(ctx, in.CatalogId, in.Name)
	if err := s.deleteDatabaseRecord(ctx, tx, "DeleteDatabase", key); err != nil {
		return nil, err
	}
	return &api.DeleteDatabaseOutput{}, nil
}
func (s *Service) deleteDatabaseRecord(ctx context.Context, tx Transaction, action string, key DatabaseKey) error {
	if err := s.authorizeDatabase(ctx, tx, action, key); err != nil {
		return err
	}
	if _, err := tx.Database(key); err != nil {
		return err
	}
	tables, err := tx.Tables(key)
	if err != nil {
		return err
	}
	functions, err := tx.Functions(key)
	if err != nil {
		return err
	}
	for _, table := range tables {
		if err := s.authorizeTable(ctx, tx, action, table.Key); err != nil {
			return err
		}
	}
	for _, function := range functions {
		if err := s.authorizeCatalog(ctx, tx, action, key.CatalogKey, key.ARN(), function.Key.ARN()); err != nil {
			return err
		}
	}
	for _, table := range tables {
		if err := deleteTableContents(tx, table.Key); err != nil {
			return err
		}
	}
	for _, function := range functions {
		if err := tx.DeleteFunction(function.Key); err != nil {
			return err
		}
	}
	return tx.DeleteDatabase(key)
}
