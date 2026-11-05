package glue

import (
	"context"
	api "stackd/internal/awsapi/glue"
)

// https://docs.aws.amazon.com/glue/latest/webapi/API_UpdateCatalog.html
func (s *Service) updateCatalog(ctx context.Context, tx Transaction, in *api.UpdateCatalogInput) (*api.UpdateCatalogOutput, error) {
	key := catalogKey(ctx, in.CatalogId)
	if err := s.authorizeCatalog(ctx, tx, "UpdateCatalog", key); err != nil {
		return nil, err
	}
	record, err := tx.Catalog(key)
	if err != nil {
		return nil, err
	}
	input := in.CatalogInput
	if input == nil {
		return nil, failure("InvalidInputException", "CatalogInput is required.")
	}
	if input.TargetRedshiftCatalog != nil || input.CatalogProperties != nil {
		return nil, unsupported("Managed catalog provisioning is not available.")
	}
	if err := s.validateFederatedCatalog(ctx, tx, key, input.FederatedCatalog); err != nil {
		return nil, err
	}
	record.Catalog.FederatedCatalog = input.FederatedCatalog
	record.Catalog.Description = input.Description
	record.Catalog.Parameters = input.Parameters
	record.Catalog.CreateDatabaseDefaultPermissions = input.CreateDatabaseDefaultPermissions
	record.Catalog.CreateTableDefaultPermissions = input.CreateTableDefaultPermissions
	record.Catalog.AllowFullTableExternalDataAccess = input.AllowFullTableExternalDataAccess
	record.Catalog.UpdateTime = new(s.clock.Now().UTC())
	return &api.UpdateCatalogOutput{}, tx.PutCatalog(record)
}
