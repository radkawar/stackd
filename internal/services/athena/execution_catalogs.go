package athena

import (
	"context"
	"errors"
	"strings"

	api "stackd/internal/awsapi/athena"
	"stackd/internal/awsctx"
)

func (s *Service) executionCatalogs(ctx context.Context, tx Transaction) ([]api.DataCatalog, error) {
	// Scheduler transactions carry the enlisted storage context, while ctx
	// carries the saved query caller used for both scope and current IAM.
	ctx = awsctx.WithMetadata(tx.Context(), awsctx.FromContext(ctx))
	rows, err := tx.Catalogs(ResourceQuery{Scope: scopeFor(ctx)})
	if err != nil {
		return nil, err
	}
	hasDefault := false
	for _, row := range rows {
		if strings.EqualFold(row.Key.Name, "AwsDataCatalog") {
			hasDefault = true
		}
	}
	if !hasDefault {
		rows = append(rows, defaultCatalog(resourceFor(ctx, "AwsDataCatalog")))
	}
	out := make([]api.DataCatalog, 0, len(rows))
	for _, row := range rows {
		if err := s.authorize(ctx, "GetDataCatalog", row.Key.ARN("datacatalog"), row.Tags, nil); err != nil {
			if wireError(err).Code == "AccessDeniedException" {
				continue
			}
			return nil, err
		}
		out = append(out, api.CloneDataCatalog(row.Data))
	}
	return out, nil
}

func (s *Service) authorizeExecutionCatalog(ctx context.Context, name, id string) error {
	return s.repository.View(ctx, func(r Reader) error {
		ctx := r.Context()
		canonical := name
		if strings.EqualFold(name, "AwsDataCatalog") {
			canonical = "AwsDataCatalog"
		}
		key := resourceFor(ctx, canonical)
		row, err := r.Catalog(key)
		if errors.Is(err, ErrNotFound) && canonical == "AwsDataCatalog" {
			row = defaultCatalog(key)
			err = nil
		}
		// Native catalog identifiers are case-insensitive. Resolve the retained
		// registration name without changing its IAM resource spelling.
		if errors.Is(err, ErrNotFound) {
			rows, readErr := r.Catalogs(ResourceQuery{Scope: key.Scope})
			if readErr != nil {
				return readErr
			}
			for _, candidate := range rows {
				if strings.EqualFold(candidate.Key.Name, name) {
					row = candidate
					err = nil
					break
				}
			}
		}
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, "GetDataCatalog", row.Key.ARN("datacatalog"), row.Tags, nil); err != nil {
			return err
		}
		if value(row.Data.Type) != "GLUE" || string(row.Data.Parameters["catalog-id"]) != id {
			return invalidRequest("The data catalog registration changed during query execution.")
		}
		return nil
	})
}
