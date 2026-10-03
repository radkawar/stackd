package s3

import (
	"database/sql"
	"time"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func objectLockTime(v time.Time) sql.NullTime {
	if v.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: v.UTC(), Valid: true}
}

func (w writer) ReplaceObjectRetention(key domain.ObjectVersionKey, retention domain.ObjectRetention) error {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	count, err := w.q.ReplaceObjectVersionRetention(w.ctx, sqlcgen.ReplaceObjectVersionRetentionParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name, VersionID: key.VersionID,
		RetentionMode: retention.Mode, RetainUntil: objectLockTime(retention.RetainUntil), EventHold: retention.EventHold,
		EventHoldDays: int64(retention.EventHoldDuration.Days), EventHoldYears: int64(retention.EventHoldDuration.Years),
		RetentionModified: objectLockTime(retention.Modified),
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (w writer) ReplaceObjectLegalHold(key domain.ObjectVersionKey, status string, modified time.Time) error {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	count, err := w.q.ReplaceObjectVersionLegalHold(w.ctx, sqlcgen.ReplaceObjectVersionLegalHoldParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name, VersionID: key.VersionID,
		LegalHold: status, LegalHoldModified: objectLockTime(modified),
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrNotFound
	}
	return nil
}
