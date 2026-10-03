package s3

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) BucketTieringConfiguration(key domain.BucketKey, id string) (*domain.TieringConfiguration, error) {
	row, err := r.q.GetBucketTieringConfiguration(r.ctx, sqlcgen.GetBucketTieringConfigurationParams{Partition: key.Partition, BucketName: key.Name, ID: id})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	config, err := r.tieringConfiguration(row)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func (r reader) BucketTieringConfigurations(query domain.BucketConfigurationQuery) ([]domain.TieringConfiguration, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if query.Limit <= 0 {
		return []domain.TieringConfiguration{}, nil
	}
	rows, err := r.q.ListBucketTieringConfigurations(r.ctx, sqlcgen.ListBucketTieringConfigurationsParams{
		Partition: query.Bucket.Partition, BucketName: query.Bucket.Name, After: query.After, PageLimit: int64(query.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.TieringConfiguration, len(rows))
	for i, row := range rows {
		out[i], err = r.tieringConfiguration(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r reader) tieringConfiguration(row sqlcgen.S3BucketTieringConfiguration) (domain.TieringConfiguration, error) {
	out := domain.TieringConfiguration{ID: row.ID, Enabled: row.Enabled, ParentEventID: row.ParentEventID}
	if row.HasFilter {
		out.Filter = &domain.ObjectFilter{Kind: row.FilterKind, Prefix: row.FilterPrefix}
		tags, err := r.q.GetBucketTieringTags(r.ctx, sqlcgen.GetBucketTieringTagsParams{
			Partition: row.Partition, BucketName: row.BucketName, ConfigurationID: row.ID,
		})
		if err != nil {
			return domain.TieringConfiguration{}, err
		}
		out.Filter.Tags = make([]domain.Tag, len(tags))
		for i, tag := range tags {
			out.Filter.Tags[i] = domain.Tag{Key: tag.Key, Value: tag.Value}
		}
	}
	rules, err := r.q.GetBucketTieringRules(r.ctx, sqlcgen.GetBucketTieringRulesParams{
		Partition: row.Partition, BucketName: row.BucketName, ConfigurationID: row.ID,
	})
	if err != nil {
		return domain.TieringConfiguration{}, err
	}
	out.Tierings = make([]domain.TieringRule, len(rules))
	for i, rule := range rules {
		out.Tierings[i] = domain.TieringRule{AccessTier: domain.AccessTier(rule.AccessTier), Days: int32(rule.Days)}
	}
	return out, nil
}

func (r reader) BucketTieringConfigurationCount(key domain.BucketKey) (int, error) {
	count, err := r.q.CountBucketTieringConfigurations(r.ctx, sqlcgen.CountBucketTieringConfigurationsParams{Partition: key.Partition, BucketName: key.Name})
	return int(count), err
}

func (r reader) BucketHasEnabledTiering(key domain.BucketKey) (bool, error) {
	return r.q.BucketHasEnabledTiering(r.ctx, sqlcgen.BucketHasEnabledTieringParams{Partition: key.Partition, BucketName: key.Name})
}

func (r reader) NextTieringScan() (*domain.BucketScan, error) {
	row, err := r.q.NextTieringScan(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &domain.BucketScan{Bucket: domain.BucketKey{Partition: row.Partition, Name: row.BucketName}, Due: row.Due}, nil
}

func (w writer) PutBucketTieringConfiguration(key domain.BucketKey, config domain.TieringConfiguration) error {
	if err := w.q.DeleteBucketTieringConfiguration(w.ctx, sqlcgen.DeleteBucketTieringConfigurationParams{Partition: key.Partition, BucketName: key.Name, ID: config.ID}); err != nil {
		return err
	}
	row := sqlcgen.PutBucketTieringConfigurationParams{
		Partition: key.Partition, BucketName: key.Name, ID: config.ID,
		Enabled: config.Enabled, ParentEventID: config.ParentEventID, HasFilter: config.Filter != nil,
	}
	if config.Filter != nil {
		row.FilterKind, row.FilterPrefix = config.Filter.Kind, config.Filter.Prefix
	}
	if err := w.q.PutBucketTieringConfiguration(w.ctx, row); err != nil {
		return err
	}
	if config.Filter != nil {
		for position, tag := range config.Filter.Tags {
			if err := w.q.PutBucketTieringTag(w.ctx, sqlcgen.PutBucketTieringTagParams{
				Partition: key.Partition, BucketName: key.Name, ConfigurationID: config.ID,
				Position: int64(position), Key: tag.Key, Value: tag.Value,
			}); err != nil {
				return err
			}
		}
	}
	for position, rule := range config.Tierings {
		if err := w.q.PutBucketTieringRule(w.ctx, sqlcgen.PutBucketTieringRuleParams{
			Partition: key.Partition, BucketName: key.Name, ConfigurationID: config.ID,
			Position: int64(position), AccessTier: string(rule.AccessTier), Days: int64(rule.Days),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteBucketTieringConfiguration(key domain.BucketKey, id string) error {
	return w.q.DeleteBucketTieringConfiguration(w.ctx, sqlcgen.DeleteBucketTieringConfigurationParams{Partition: key.Partition, BucketName: key.Name, ID: id})
}

func (w writer) SetTieringScan(key domain.BucketKey, due *time.Time) error {
	if due == nil {
		return w.q.DeleteTieringScan(w.ctx, sqlcgen.DeleteTieringScanParams{Partition: key.Partition, BucketName: key.Name})
	}
	return w.q.PutTieringScan(w.ctx, sqlcgen.PutTieringScanParams{Partition: key.Partition, BucketName: key.Name, Due: due.UTC()})
}

func (w writer) SetObjectTiering(key domain.ObjectVersionKey, createdOrder int64, tiering *domain.ObjectTiering) error {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	row := sqlcgen.SetObjectTieringParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name,
		VersionID: key.VersionID, CreatedOrder: createdOrder,
	}
	if tiering != nil {
		row.TieringAccessed = new(tiering.Accessed.UTC())
		row.ArchiveTier = string(tiering.ArchiveTier)
	}
	return w.q.SetObjectTiering(w.ctx, row)
}
