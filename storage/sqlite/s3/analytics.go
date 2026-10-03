package s3

import (
	"database/sql"
	"errors"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func analyticsConfiguration(row sqlcgen.S3BucketAnalyticsConfiguration) domain.AnalyticsConfiguration {
	out := domain.AnalyticsConfiguration{ID: row.ID}
	if row.FilterKind != nil {
		out.Filter = &domain.ObjectFilter{Kind: *row.FilterKind, Prefix: row.FilterPrefix}
	}
	if row.DestinationBucketArn != nil {
		out.Destination = &domain.AnalyticsDestination{BucketARN: *row.DestinationBucketArn, AccountID: row.DestinationAccountID, Prefix: row.DestinationPrefix}
	}
	return out
}

func (r reader) BucketAnalyticsConfiguration(key domain.BucketKey, id string) (*domain.AnalyticsConfiguration, error) {
	row, err := r.q.GetBucketAnalyticsConfiguration(r.ctx, sqlcgen.GetBucketAnalyticsConfigurationParams{Partition: key.Partition, BucketName: key.Name, ID: id})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := analyticsConfiguration(row)
	if out.Filter != nil {
		tags, err := r.q.GetBucketAnalyticsTags(r.ctx, sqlcgen.GetBucketAnalyticsTagsParams{Partition: key.Partition, BucketName: key.Name, ConfigurationID: id})
		if err != nil {
			return nil, err
		}
		out.Filter.Tags = make([]domain.Tag, len(tags))
		for i, tag := range tags {
			out.Filter.Tags[i] = domain.Tag{Key: tag.Key, Value: tag.Value}
		}
	}
	return &out, nil
}

func (r reader) BucketAnalyticsConfigurations(query domain.BucketConfigurationQuery) ([]domain.AnalyticsConfiguration, error) {
	if query.Limit <= 0 {
		return []domain.AnalyticsConfiguration{}, r.ctx.Err()
	}
	rows, err := r.q.ListBucketAnalyticsConfigurations(r.ctx, sqlcgen.ListBucketAnalyticsConfigurationsParams{
		Partition: query.Bucket.Partition, BucketName: query.Bucket.Name, After: query.After, PageLimit: int64(query.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := []domain.AnalyticsConfiguration{}
	for _, row := range rows {
		config := row.S3BucketAnalyticsConfiguration
		if len(out) == 0 || out[len(out)-1].ID != config.ID {
			out = append(out, analyticsConfiguration(config))
		}
		if row.TagPosition.Valid {
			filter := out[len(out)-1].Filter
			filter.Tags = append(filter.Tags, domain.Tag{Key: row.TagKey.String, Value: row.TagValue.String})
		}
	}
	return out, nil
}

func (r reader) BucketAnalyticsConfigurationCount(key domain.BucketKey) (int, error) {
	count, err := r.q.CountBucketAnalyticsConfigurations(r.ctx, sqlcgen.CountBucketAnalyticsConfigurationsParams{Partition: key.Partition, BucketName: key.Name})
	return int(count), err
}

func (w writer) PutBucketAnalyticsConfiguration(key domain.BucketKey, config domain.AnalyticsConfiguration) error {
	if err := w.DeleteBucketAnalyticsConfiguration(key, config.ID); err != nil {
		return err
	}
	row := sqlcgen.PutBucketAnalyticsConfigurationParams{Partition: key.Partition, BucketName: key.Name, ID: config.ID}
	if config.Filter != nil {
		row.FilterKind, row.FilterPrefix = new(config.Filter.Kind), config.Filter.Prefix
	}
	if config.Destination != nil {
		row.DestinationBucketArn = new(config.Destination.BucketARN)
		row.DestinationAccountID, row.DestinationPrefix = config.Destination.AccountID, config.Destination.Prefix
	}
	if err := w.q.PutBucketAnalyticsConfiguration(w.ctx, row); err != nil {
		return err
	}
	if config.Filter != nil {
		for position, tag := range config.Filter.Tags {
			if err := w.q.PutBucketAnalyticsTag(w.ctx, sqlcgen.PutBucketAnalyticsTagParams{
				Partition: key.Partition, BucketName: key.Name, ConfigurationID: config.ID,
				Position: int64(position), Key: tag.Key, Value: tag.Value,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w writer) DeleteBucketAnalyticsConfiguration(key domain.BucketKey, id string) error {
	return w.q.DeleteBucketAnalyticsConfiguration(w.ctx, sqlcgen.DeleteBucketAnalyticsConfigurationParams{Partition: key.Partition, BucketName: key.Name, ID: id})
}
