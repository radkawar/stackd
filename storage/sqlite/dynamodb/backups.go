package dynamodb

import (
	"database/sql"
	"errors"
	"time"

	api "stackd/internal/awsapi/dynamodb"
	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
)

func (r reader) Backup(k domain.BackupKey) (domain.BackupRecord, error) {
	row, err := r.q.GetBackup(r.ctx, sqlcgen.GetBackupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TableName: k.TableName, BackupID: k.ID})
	if err != nil {
		return domain.BackupRecord{}, missing(err)
	}
	return backupData(row)
}

func (r reader) Backups(q domain.BackupQuery) ([]domain.BackupRecord, error) {
	rows, err := r.q.ListBackups(r.ctx, sqlcgen.ListBackupsParams{
		Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, SourceTable: q.TableName, AfterArn: q.After,
		Kind: q.Type, At: sql.NullTime{Time: q.At, Valid: true},
		LowerTime: sql.NullTime{Time: q.Lower, Valid: !q.Lower.IsZero()}, UpperTime: sql.NullTime{Time: q.Upper, Valid: !q.Upper.IsZero()}, RowLimit: rowLimit(q.Limit),
	})
	if err != nil {
		return nil, err
	}
	return backupRows(rows)
}

func (r reader) PendingBackups(now time.Time) ([]domain.BackupRecord, error) {
	rows, err := r.q.ListPendingBackups(r.ctx, sql.NullTime{Time: now, Valid: true})
	if err != nil {
		return nil, err
	}
	return backupRows(rows)
}

func (r reader) NextBackupExpiry(after time.Time) (time.Time, error) {
	next, err := r.q.NextBackupExpiry(r.ctx, sql.NullTime{Time: after, Valid: true})
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	return next.Time, err
}

func (r reader) UncapturedBackups(databaseID string) ([]domain.BackupRecord, error) {
	rows, err := r.q.ListUncapturedBackups(r.ctx, databaseID)
	if err != nil {
		return nil, err
	}
	return backupRows(rows)
}

func (r reader) HasDatabaseBackups(databaseID string) (bool, error) {
	return r.q.HasDatabaseBackups(r.ctx, databaseID)
}

func backupRows(rows []sqlcgen.DynamodbBackup) ([]domain.BackupRecord, error) {
	out := make([]domain.BackupRecord, 0, len(rows))
	for _, row := range rows {
		v, err := backupData(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func backupData(row sqlcgen.DynamodbBackup) (domain.BackupRecord, error) {
	key := domain.BackupKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, TableName: row.TableName, ID: row.BackupID}
	source := &api.SourceTableDetails{
		TableName: new(api.TableName(key.TableName)), TableArn: new(api.TableArn((domain.TableKey{Scope: key.Scope, Name: key.TableName}).ARN())),
		TableId: new(api.TableId(row.SourceTableID)), TableCreationDateTime: &row.SourceCreatedAt,
		BillingMode: stringPointer[api.BillingMode](row.SourceBillingMode), ItemCount: integerPointer[api.ItemCount](row.SourceItemCount), TableSizeBytes: integerPointer[api.LongObject](row.SourceSizeBytes),
	}
	features := &api.SourceTableFeatureDetails{}
	if row.SourceTtlStatus.Valid {
		features.TimeToLiveDescription = &api.TimeToLiveDescription{TimeToLiveStatus: stringPointer[api.TimeToLiveStatus](row.SourceTtlStatus), AttributeName: stringPointer[api.TimeToLiveAttributeName](row.SourceTtlAttributeName)}
	}
	out := domain.BackupRecord{
		Key: key, DatabaseID: row.DatabaseID, PhysicalName: row.PhysicalName, SourcePhysicalName: row.SourcePhysicalName,
		Description: api.BackupDescription{
			BackupDetails: &api.BackupDetails{
				BackupArn: new(api.BackupArn(row.BackupArn)), BackupName: new(api.BackupName(row.BackupName)), BackupCreationDateTime: &row.BackupCreatedAt,
				BackupStatus: new(api.BackupStatus(row.BackupStatus)), BackupSizeBytes: integerPointer[api.BackupSizeBytes](row.BackupSizeBytes), BackupType: new(api.BackupType(row.BackupType)),
			},
			SourceTableDetails: source, SourceTableFeatureDetails: features,
		},
	}
	if row.BackupExpiresAt.Valid {
		out.Description.BackupDetails.BackupExpiryDateTime = &row.BackupExpiresAt.Time
	}
	err := unmarshalFields(
		jsonReadField{row.AttributeDefinitions, &out.AttributeDefinitions}, jsonReadField{row.SourceKeySchema, &source.KeySchema},
		jsonReadField{row.SourceProvisionedThroughput, &source.ProvisionedThroughput}, jsonReadField{row.SourceOnDemandThroughput, &source.OnDemandThroughput},
		jsonReadField{row.SourceGlobalSecondaryIndexes, &features.GlobalSecondaryIndexes}, jsonReadField{row.SourceLocalSecondaryIndexes, &features.LocalSecondaryIndexes},
		jsonReadField{row.SourceStreamDescription, &features.StreamDescription},
	)
	return out, err
}

func (w writer) PutBackup(v domain.BackupRecord) error {
	k, d := v.Key, v.Description.BackupDetails
	source, features := v.Description.SourceTableDetails, v.Description.SourceTableFeatureDetails
	params := sqlcgen.PutBackupParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TableName: k.TableName, BackupID: k.ID,
		BackupArn: string(*d.BackupArn), DatabaseID: v.DatabaseID, PhysicalName: v.PhysicalName, SourcePhysicalName: v.SourcePhysicalName,
		BackupName: string(*d.BackupName), BackupCreatedAt: *d.BackupCreationDateTime, BackupStatus: string(*d.BackupStatus), BackupSizeBytes: nullableInteger(d.BackupSizeBytes),
		BackupType: string(*d.BackupType), BackupExpiresAt: nullableTime(d.BackupExpiryDateTime),
		SourceTableID: string(*source.TableId), SourceCreatedAt: *source.TableCreationDateTime, SourceBillingMode: nullableString(source.BillingMode),
		SourceItemCount: nullableInteger(source.ItemCount), SourceSizeBytes: nullableInteger(source.TableSizeBytes),
	}
	if features.TimeToLiveDescription != nil {
		params.SourceTtlAttributeName = nullableString(features.TimeToLiveDescription.AttributeName)
		params.SourceTtlStatus = nullableString(features.TimeToLiveDescription.TimeToLiveStatus)
	}
	if err := marshalFields(
		jsonWriteField{&params.AttributeDefinitions, v.AttributeDefinitions}, jsonWriteField{&params.SourceKeySchema, source.KeySchema},
		jsonWriteField{&params.SourceProvisionedThroughput, source.ProvisionedThroughput}, jsonWriteField{&params.SourceOnDemandThroughput, source.OnDemandThroughput},
		jsonWriteField{&params.SourceGlobalSecondaryIndexes, features.GlobalSecondaryIndexes}, jsonWriteField{&params.SourceLocalSecondaryIndexes, features.LocalSecondaryIndexes},
		jsonWriteField{&params.SourceStreamDescription, features.StreamDescription},
	); err != nil {
		return err
	}
	return w.q.PutBackup(w.ctx, params)
}

func (w writer) DeleteBackup(k domain.BackupKey) error {
	return w.q.DeleteBackup(w.ctx, sqlcgen.DeleteBackupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TableName: k.TableName, BackupID: k.ID})
}
