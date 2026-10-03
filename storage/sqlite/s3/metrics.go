package s3

import (
	"database/sql"
	"errors"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func metricsConfiguration(row sqlcgen.S3BucketMetricsConfiguration) domain.RequestMetricsConfiguration {
	out := domain.RequestMetricsConfiguration{ID: row.ID}
	if row.FilterKind != nil {
		out.Filter = &domain.RequestMetricsFilter{
			ObjectFilter:   domain.ObjectFilter{Kind: *row.FilterKind, Prefix: row.FilterPrefix},
			AccessPointARN: row.AccessPointArn,
		}
	}
	return out
}

func (r reader) BucketMetricsConfiguration(key domain.BucketKey, id string) (*domain.RequestMetricsConfiguration, error) {
	row, err := r.q.GetBucketMetricsConfiguration(r.ctx, sqlcgen.GetBucketMetricsConfigurationParams{Partition: key.Partition, BucketName: key.Name, ID: id})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := metricsConfiguration(row)
	if out.Filter != nil {
		tags, err := r.q.GetBucketMetricsTags(r.ctx, sqlcgen.GetBucketMetricsTagsParams{Partition: key.Partition, BucketName: key.Name, ConfigurationID: id})
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

func (r reader) BucketMetricsConfigurations(query domain.BucketConfigurationQuery) ([]domain.RequestMetricsConfiguration, error) {
	if query.Limit <= 0 {
		return []domain.RequestMetricsConfiguration{}, r.ctx.Err()
	}
	// HTTP accounting loads the whole selector set. The join retains ordered
	// tags in one query rather than a query per enabled configuration.
	rows, err := r.q.ListBucketMetricsConfigurations(r.ctx, sqlcgen.ListBucketMetricsConfigurationsParams{
		Partition: query.Bucket.Partition, BucketName: query.Bucket.Name, After: query.After, PageLimit: int64(query.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := []domain.RequestMetricsConfiguration{}
	for _, row := range rows {
		config := row.S3BucketMetricsConfiguration
		if len(out) == 0 || out[len(out)-1].ID != config.ID {
			out = append(out, metricsConfiguration(config))
		}
		if row.TagPosition.Valid {
			filter := out[len(out)-1].Filter
			filter.Tags = append(filter.Tags, domain.Tag{Key: row.TagKey.String, Value: row.TagValue.String})
		}
	}
	return out, nil
}

func (r reader) BucketMetricsConfigurationCount(key domain.BucketKey) (int, error) {
	count, err := r.q.CountBucketMetricsConfigurations(r.ctx, sqlcgen.CountBucketMetricsConfigurationsParams{Partition: key.Partition, BucketName: key.Name})
	return int(count), err
}

func (w writer) PutBucketMetricsConfiguration(key domain.BucketKey, config domain.RequestMetricsConfiguration) error {
	if err := w.DeleteBucketMetricsConfiguration(key, config.ID); err != nil {
		return err
	}
	row := sqlcgen.PutBucketMetricsConfigurationParams{Partition: key.Partition, BucketName: key.Name, ID: config.ID}
	if config.Filter != nil {
		row.FilterKind, row.FilterPrefix, row.AccessPointArn = new(config.Filter.Kind), config.Filter.Prefix, config.Filter.AccessPointARN
	}
	if err := w.q.PutBucketMetricsConfiguration(w.ctx, row); err != nil {
		return err
	}
	if config.Filter != nil {
		for position, tag := range config.Filter.Tags {
			if err := w.q.PutBucketMetricsTag(w.ctx, sqlcgen.PutBucketMetricsTagParams{
				Partition: key.Partition, BucketName: key.Name, ConfigurationID: config.ID,
				Position: int64(position), Key: tag.Key, Value: tag.Value,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w writer) DeleteBucketMetricsConfiguration(key domain.BucketKey, id string) error {
	return w.q.DeleteBucketMetricsConfiguration(w.ctx, sqlcgen.DeleteBucketMetricsConfigurationParams{Partition: key.Partition, BucketName: key.Name, ID: id})
}
