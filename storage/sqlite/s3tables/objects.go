package s3tables

import (
	"context"
	"database/sql"
	"errors"
	"time"

	domain "stackd/internal/services/s3tables"
	"stackd/storage/internal/s3tablescrypt"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/s3tables/internal/sqlcgen"
)

type objectStore struct{ db *sql.DB }

// NewObjects atomically encrypts legacy bytes before exposing the private
// warehouse adapter. Encrypted rows are authenticated only when their bytes are read.
func NewObjects(ctx context.Context, db *sql.DB) (domain.WarehouseObjects, error) {
	if err := migrateObjectEncryption(ctx, db); err != nil {
		return nil, err
	}
	return &objectStore{db: db}, nil
}
func objectInfo(row sqlcgen.S3tablesObject) domain.ObjectInfo {
	attrs := domain.ObjectAttributes{ContentType: row.ContentType, CacheControl: row.CacheControl, ContentDisposition: row.ContentDisposition, ContentEncoding: row.ContentEncoding, ContentLanguage: row.ContentLanguage, ChecksumAlgorithm: row.ChecksumAlgorithm, Checksums: domain.ObjectChecksums{CRC32: row.ChecksumCrc32, CRC32C: row.ChecksumCrc32c, CRC64NVME: row.ChecksumCrc64nvme, SHA1: row.ChecksumSha1, SHA256: row.ChecksumSha256}}
	if row.ExpiresAt.Valid {
		v := row.ExpiresAt.Time.UTC()
		attrs.Expires = &v
	}
	return domain.ObjectInfo{Key: row.ObjectKey, ETag: row.Etag, Size: row.Size, Modified: row.ModifiedAt.UTC(), Attributes: attrs}
}
func nullExpires(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: value.UTC(), Valid: true}
}
func putObject(ctx context.Context, q *sqlcgen.Queries, warehouse string, data []byte, info domain.ObjectInfo) error {
	encrypted, err := s3tablescrypt.Seal(data, s3tablescrypt.ObjectIdentity(warehouse, info.Key))
	if err != nil {
		return err
	}
	a := info.Attributes
	return q.PutTableWarehouseObject(ctx, sqlcgen.PutTableWarehouseObjectParams{Warehouse: warehouse, ObjectKey: info.Key, Etag: info.ETag, Size: info.Size, ModifiedAt: info.Modified.UTC(), Content: encrypted.Data, EncryptionVersion: encrypted.Version, EncryptionAlgorithm: encrypted.Algorithm, EncryptionKey: encrypted.Key, EncryptionNonce: encrypted.Nonce, ContentType: a.ContentType, CacheControl: a.CacheControl, ContentDisposition: a.ContentDisposition, ContentEncoding: a.ContentEncoding, ContentLanguage: a.ContentLanguage, ExpiresAt: nullExpires(a.Expires), ChecksumAlgorithm: a.ChecksumAlgorithm, ChecksumCrc32: a.Checksums.CRC32, ChecksumCrc32c: a.Checksums.CRC32C, ChecksumCrc64nvme: a.Checksums.CRC64NVME, ChecksumSha1: a.Checksums.SHA1, ChecksumSha256: a.Checksums.SHA256})
}
func physicalGuard(ctx context.Context, guard domain.PublicationGuard) error {
	if guard != nil {
		return guard(ctx)
	}
	return nil
}
func (r *objectStore) Read(ctx context.Context, warehouse, key string) ([]byte, error) {
	data, _, err := r.ReadObject(ctx, warehouse, key)
	return data, err
}
func (r *objectStore) ReadObject(ctx context.Context, warehouse, key string) ([]byte, domain.ObjectInfo, error) {
	var row sqlcgen.S3tablesObject
	err := sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		row, err = sqlcgen.New(tx).GetTableWarehouseObject(ctx, sqlcgen.GetTableWarehouseObjectParams{Warehouse: warehouse, ObjectKey: key})
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ObjectInfo{}, domain.ErrNotFound
	}
	if err != nil {
		return nil, domain.ObjectInfo{}, err
	}
	data, err := openObject(row, warehouse, key)
	if err != nil {
		return nil, domain.ObjectInfo{}, err
	}
	return data, objectInfo(row), nil
}
func (r *objectStore) Write(ctx context.Context, warehouse, key string, data []byte, modified time.Time) error {
	info, err := domain.SingleObjectInfo(key, data, domain.ObjectAttributes{}, modified)
	if err != nil {
		return err
	}
	_, err = r.WriteObject(ctx, warehouse, data, info, domain.ObjectConditions{}, nil)
	return err
}
func objectExists(ctx context.Context, q *sqlcgen.Queries, warehouse, key string) (bool, error) {
	_, err := q.GetTableWarehouseObjectKey(ctx, sqlcgen.GetTableWarehouseObjectKeyParams{Warehouse: warehouse, ObjectKey: key})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
func (r *objectStore) WriteObject(ctx context.Context, warehouse string, data []byte, info domain.ObjectInfo, conditions domain.ObjectConditions, guard domain.PublicationGuard) (domain.ObjectInfo, error) {
	err := sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		exists, err := objectExists(ctx, q, warehouse, info.Key)
		if err != nil {
			return err
		}
		// Revoked authority must not be masked by an existing destination.
		if err = physicalGuard(ctx, guard); err != nil {
			return err
		}
		if err = domain.CheckObjectConditions(exists, conditions); err != nil {
			return err
		}
		if err = putObject(ctx, q, warehouse, data, info); err != nil {
			return err
		}
		return physicalGuard(ctx, guard)
	})
	return info, err
}
func (r *objectStore) Delete(ctx context.Context, warehouse, key string) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		return sqlcgen.New(tx).DeleteTableWarehouseObject(ctx, sqlcgen.DeleteTableWarehouseObjectParams{Warehouse: warehouse, ObjectKey: key})
	})
}
func (r *objectStore) List(ctx context.Context, warehouse, prefix string) ([]domain.ObjectInfo, error) {
	var objects []domain.ObjectInfo
	err := sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := sqlcgen.New(tx).ListTableWarehouseObjects(ctx, sqlcgen.ListTableWarehouseObjectsParams{Warehouse: warehouse, PrefixStart: prefix, PrefixEnd: prefix + "\xff"})
		if err != nil {
			return err
		}
		objects = make([]domain.ObjectInfo, len(rows))
		for i, row := range rows {
			objects[i] = objectInfo(sqlcgen.S3tablesObject{ObjectKey: row.ObjectKey, Etag: row.Etag, Size: row.Size, ModifiedAt: row.ModifiedAt, ContentType: row.ContentType, CacheControl: row.CacheControl, ContentDisposition: row.ContentDisposition, ContentEncoding: row.ContentEncoding, ContentLanguage: row.ContentLanguage, ExpiresAt: row.ExpiresAt, ChecksumAlgorithm: row.ChecksumAlgorithm, ChecksumCrc32: row.ChecksumCrc32, ChecksumCrc32c: row.ChecksumCrc32c, ChecksumCrc64nvme: row.ChecksumCrc64nvme, ChecksumSha1: row.ChecksumSha1, ChecksumSha256: row.ChecksumSha256})
		}
		return nil
	})
	return objects, err
}
func (r *objectStore) PurgeWarehouse(ctx context.Context, warehouse string) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		if err := q.DeleteTableMultipartUploads(ctx, warehouse); err != nil {
			return err
		}
		return q.DeleteTableWarehouseObjects(ctx, warehouse)
	})
}
