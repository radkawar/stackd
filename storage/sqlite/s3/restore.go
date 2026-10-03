package s3

import (
	"database/sql"
	"errors"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) ObjectRestore(key domain.ObjectVersionKey) (*domain.ObjectRestore, error) {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	row, err := r.q.GetObjectRestore(r.ctx, sqlcgen.GetObjectRestoreParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return objectRestore(row), nil
}

func (r reader) NextObjectRestore() (*domain.ObjectRestore, error) {
	row, err := r.q.NextObjectRestore(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return objectRestore(row), nil
}

func objectRestore(row sqlcgen.S3ObjectRestore) *domain.ObjectRestore {
	return &domain.ObjectRestore{
		Key: domain.ObjectVersionKey{
			ObjectKey: domain.ObjectKey{Bucket: domain.BucketKey{Partition: row.Partition, Name: row.BucketName}, Name: row.ObjectName},
			VersionID: row.VersionID,
		},
		Due: row.Due, Ongoing: row.Ongoing, Days: int32(row.Days), Tier: row.Tier, ParentEventID: row.ParentEventID,
	}
}

func (w writer) PutObjectRestore(value domain.ObjectRestore) error {
	key := value.Key
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	return w.q.PutObjectRestore(w.ctx, sqlcgen.PutObjectRestoreParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
		Due: value.Due.UTC(), Ongoing: value.Ongoing, Days: int64(value.Days), Tier: value.Tier, ParentEventID: value.ParentEventID,
	})
}

func (w writer) DeleteObjectRestore(key domain.ObjectVersionKey) error {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	return w.q.DeleteObjectRestore(w.ctx, sqlcgen.DeleteObjectRestoreParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
	})
}
