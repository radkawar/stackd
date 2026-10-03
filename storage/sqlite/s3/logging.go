package s3

import (
	"database/sql"
	"errors"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) BucketLogging(key domain.BucketKey) (*domain.LoggingConfiguration, error) {
	row, err := r.q.GetBucketLogging(r.ctx, sqlcgen.GetBucketLoggingParams{Partition: key.Partition, BucketName: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &domain.LoggingConfiguration{TargetBucket: row.TargetBucket, TargetPrefix: row.TargetPrefix, KeyFormat: row.KeyFormat}
	if !row.HasGrants {
		return out, nil
	}
	grants, err := r.q.GetBucketLoggingGrants(r.ctx, sqlcgen.GetBucketLoggingGrantsParams{Partition: key.Partition, BucketName: key.Name})
	if err != nil {
		return nil, err
	}
	out.Grants = make([]domain.ACLGrant, len(grants))
	for i, grant := range grants {
		out.Grants[i] = domain.ACLGrant{Type: grant.GranteeType, ID: grant.GranteeID, URI: grant.GranteeUri, Permission: grant.Permission}
	}
	return out, nil
}

func (w writer) ReplaceBucketLogging(key domain.BucketKey, config *domain.LoggingConfiguration) error {
	if err := w.q.DeleteBucketLogging(w.ctx, sqlcgen.DeleteBucketLoggingParams{Partition: key.Partition, BucketName: key.Name}); err != nil {
		return err
	}
	if config == nil {
		return nil
	}
	if err := w.q.PutBucketLogging(w.ctx, sqlcgen.PutBucketLoggingParams{
		Partition: key.Partition, BucketName: key.Name, TargetBucket: config.TargetBucket,
		TargetPrefix: config.TargetPrefix, KeyFormat: config.KeyFormat, HasGrants: config.Grants != nil,
	}); err != nil {
		return err
	}
	for position, grant := range config.Grants {
		if err := w.q.PutBucketLoggingGrant(w.ctx, sqlcgen.PutBucketLoggingGrantParams{
			Partition: key.Partition, BucketName: key.Name, Position: int64(position),
			GranteeType: grant.Type, GranteeID: grant.ID, GranteeUri: grant.URI, Permission: grant.Permission,
		}); err != nil {
			return err
		}
	}
	return nil
}
