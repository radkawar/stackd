package s3tables

import (
	"context"
	"database/sql"
	"errors"

	domain "stackd/internal/services/s3tables"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/s3tables/internal/sqlcgen"
)

func (r *objectStore) Info(ctx context.Context, warehouse, key string) (domain.ObjectInfo, error) {
	var info domain.ObjectInfo
	err := sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		row, err := sqlcgen.New(tx).GetTableWarehouseObjectInfo(ctx, sqlcgen.GetTableWarehouseObjectInfoParams{Warehouse: warehouse, ObjectKey: key})
		if err != nil {
			return err
		}
		info = objectInfo(sqlcgen.S3tablesObject{ObjectKey: row.ObjectKey, Etag: row.Etag, Size: row.Size, ModifiedAt: row.ModifiedAt, ContentType: row.ContentType, CacheControl: row.CacheControl, ContentDisposition: row.ContentDisposition, ContentEncoding: row.ContentEncoding, ContentLanguage: row.ContentLanguage, ExpiresAt: row.ExpiresAt, ChecksumAlgorithm: row.ChecksumAlgorithm, ChecksumCrc32: row.ChecksumCrc32, ChecksumCrc32c: row.ChecksumCrc32c, ChecksumCrc64nvme: row.ChecksumCrc64nvme, ChecksumSha1: row.ChecksumSha1, ChecksumSha256: row.ChecksumSha256})
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ObjectInfo{}, domain.ErrNotFound
	}
	return info, err
}
