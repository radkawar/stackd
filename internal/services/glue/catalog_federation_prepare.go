package glue

import (
	"context"

	api "stackd/internal/awsapi/glue"
	tables "stackd/internal/awsapi/s3tables"
	managed "stackd/internal/services/s3tables"
)

type federatedMetadataContextKey struct{}
type federatedMetadataPublication struct {
	catalog  CatalogKey
	input    *tables.UpdateTableMetadataLocationInput
	prepared *managed.PreparedTableMetadataUpdate
}

// prepareFederatedCommand validates immutable warehouse bytes before the Glue
// mutation transaction. Publication later rechecks both Glue and S3 Tables IAM
// and the exact owner's token in that shared transaction.
func (s *Service) prepareFederatedCommand(ctx context.Context, action string, input any) (context.Context, error) {
	if in, ok := input.(*api.CreateTableInput); ok && action == "CreateTable" {
		return s.prepareFederatedCreate(ctx, in)
	}
	in, ok := input.(*api.UpdateTableInput)
	if !ok || action != "UpdateTable" || in.TableInput == nil {
		return ctx, nil
	}
	var publication federatedMetadataPublication
	var mounted bool
	e := s.repository.Attempt(ctx, func(tx Transaction) error {
		key := tableKey(tx.Context(), in.CatalogId, in.DatabaseName, in.TableInput.Name)
		bucket, found, e := s.mountedBucket(tx.Context(), tx, key.CatalogKey)
		if e != nil {
			return e
		}
		mounted = found
		if !found {
			return nil
		}
		if e = s.authorizeCatalog(tx.Context(), tx, "GetCatalog", key.CatalogKey); e != nil {
			return e
		}
		if e = s.authorizeTable(tx.Context(), tx, "UpdateTable", key); e != nil {
			return e
		}
		if e = validateFederatedTableInput(in.TableInput); e != nil {
			return e
		}
		if value(in.VersionId) == "" {
			return failure("InvalidInputException", "The current S3 Tables version token is required as VersionId.")
		}
		if in.TransactionId != nil || in.UpdateOpenTableFormatInput != nil || in.ViewUpdateAction != nil {
			return unsupported("Use the S3 Tables metadata-location operation to commit native metadata.")
		}
		publication.catalog = key.CatalogKey
		publication.input = &tables.UpdateTableMetadataLocationInput{TableBucketARN: new(tables.TableBucketARN(bucket)), Namespace: new(tables.NamespaceName(key.Name)), Name: new(tables.TableName(key.TableName)), VersionToken: new(tables.VersionToken(value(in.VersionId))), MetadataLocation: new(tables.MetadataLocation(in.TableInput.Parameters["metadata_location"]))}
		return nil
	})
	if e != nil || !mounted {
		return ctx, e
	}
	var rejected error
	prepared, wire := s.s3Tables.PrepareTableMetadataUpdate(ctx, publication.input)
	if wire != nil {
		rejected = federationError(wire)
		return ctx, rejected
	}
	publication.prepared = prepared
	return context.WithValue(ctx, federatedMetadataContextKey{}, &publication), nil
}
