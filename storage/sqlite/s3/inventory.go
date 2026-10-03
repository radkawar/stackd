package s3

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func inventoryConfiguration(row sqlcgen.S3BucketInventoryConfiguration) domain.InventoryConfiguration {
	out := domain.InventoryConfiguration{
		ID: row.ID, Enabled: row.Enabled, AllVersions: row.AllVersions, Weekly: row.Weekly,
		FilterPrefix: row.FilterPrefix, ParentEventID: row.ParentEventID, NextReport: row.NextReport,
		Destination: domain.InventoryDestination{
			BucketARN: row.DestinationBucketArn, AccountID: row.DestinationAccountID, Prefix: row.DestinationPrefix,
			Format: row.Format, Encryption: row.Encryption, KMSKeyID: row.KmsKeyID,
		},
	}
	if row.OptionalFieldsPresent {
		out.OptionalFields = []string{}
	}
	return out
}

func (r reader) inventoryConfiguration(row sqlcgen.S3BucketInventoryConfiguration) (*domain.InventoryConfiguration, error) {
	out := inventoryConfiguration(row)
	if row.OptionalFieldsPresent {
		fields, err := r.q.GetBucketInventoryOptionalFields(r.ctx, sqlcgen.GetBucketInventoryOptionalFieldsParams{
			Partition: row.Partition, BucketName: row.BucketName, ConfigurationID: row.ID,
		})
		if err != nil {
			return nil, err
		}
		out.OptionalFields = make([]string, len(fields))
		for i, field := range fields {
			out.OptionalFields[i] = field.Field
		}
	}
	return &out, nil
}

func (r reader) BucketInventoryConfiguration(key domain.BucketKey, id string) (*domain.InventoryConfiguration, error) {
	row, err := r.q.GetBucketInventoryConfiguration(r.ctx, sqlcgen.GetBucketInventoryConfigurationParams{Partition: key.Partition, BucketName: key.Name, ID: id})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r.inventoryConfiguration(row)
}

func (r reader) BucketInventoryConfigurations(query domain.BucketConfigurationQuery) ([]domain.InventoryConfiguration, error) {
	if query.Limit <= 0 {
		return []domain.InventoryConfiguration{}, r.ctx.Err()
	}
	rows, err := r.q.ListBucketInventoryConfigurations(r.ctx, sqlcgen.ListBucketInventoryConfigurationsParams{
		Partition: query.Bucket.Partition, BucketName: query.Bucket.Name, After: query.After, PageLimit: int64(query.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := []domain.InventoryConfiguration{}
	for _, row := range rows {
		config := row.S3BucketInventoryConfiguration
		if len(out) == 0 || out[len(out)-1].ID != config.ID {
			out = append(out, inventoryConfiguration(config))
		}
		if row.FieldPosition.Valid {
			last := &out[len(out)-1]
			last.OptionalFields = append(last.OptionalFields, row.OptionalField.String)
		}
	}
	return out, nil
}

func (r reader) BucketInventoryConfigurationCount(key domain.BucketKey) (int, error) {
	count, err := r.q.CountBucketInventoryConfigurations(r.ctx, sqlcgen.CountBucketInventoryConfigurationsParams{Partition: key.Partition, BucketName: key.Name})
	return int(count), err
}

func (r reader) NextInventoryConfiguration() (domain.BucketKey, *domain.InventoryConfiguration, error) {
	row, err := r.q.NextInventoryConfiguration(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.BucketKey{}, nil, nil
	}
	if err != nil {
		return domain.BucketKey{}, nil, err
	}
	config, err := r.inventoryConfiguration(row)
	if err != nil {
		return domain.BucketKey{}, nil, err
	}
	return domain.BucketKey{Partition: row.Partition, Name: row.BucketName}, config, nil
}

func (w writer) PutBucketInventoryConfiguration(key domain.BucketKey, config domain.InventoryConfiguration) error {
	if err := w.DeleteBucketInventoryConfiguration(key, config.ID); err != nil {
		return err
	}
	if err := w.q.PutBucketInventoryConfiguration(w.ctx, sqlcgen.PutBucketInventoryConfigurationParams{
		Partition: key.Partition, BucketName: key.Name, ID: config.ID,
		Enabled: config.Enabled, AllVersions: config.AllVersions, Weekly: config.Weekly,
		FilterPrefix: config.FilterPrefix, OptionalFieldsPresent: config.OptionalFields != nil,
		DestinationBucketArn: config.Destination.BucketARN, DestinationAccountID: config.Destination.AccountID,
		DestinationPrefix: config.Destination.Prefix, Format: config.Destination.Format,
		Encryption: config.Destination.Encryption, KmsKeyID: config.Destination.KMSKeyID,
		ParentEventID: config.ParentEventID, NextReport: config.NextReport.UTC(),
	}); err != nil {
		return err
	}
	for position, field := range config.OptionalFields {
		if err := w.q.PutBucketInventoryOptionalField(w.ctx, sqlcgen.PutBucketInventoryOptionalFieldParams{
			Partition: key.Partition, BucketName: key.Name, ConfigurationID: config.ID, Position: int64(position), Field: field,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteBucketInventoryConfiguration(key domain.BucketKey, id string) error {
	return w.q.DeleteBucketInventoryConfiguration(w.ctx, sqlcgen.DeleteBucketInventoryConfigurationParams{Partition: key.Partition, BucketName: key.Name, ID: id})
}

func (w writer) AdvanceInventoryReport(key domain.BucketKey, id, parentEventID string, previous, next time.Time) error {
	return w.q.AdvanceInventoryReport(w.ctx, sqlcgen.AdvanceInventoryReportParams{
		Partition: key.Partition, BucketName: key.Name, ID: id, ParentEventID: parentEventID,
		PreviousReport: previous.UTC(), NextReport: next.UTC(),
	})
}
