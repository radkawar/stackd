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

func multipartUpload(row sqlcgen.S3tablesMultipartUpload) domain.MultipartUpload {
	a := domain.ObjectAttributes{ContentType: row.ContentType, CacheControl: row.CacheControl, ContentDisposition: row.ContentDisposition, ContentEncoding: row.ContentEncoding, ContentLanguage: row.ContentLanguage, ChecksumAlgorithm: row.ChecksumAlgorithm}
	if row.ExpiresAt.Valid {
		v := row.ExpiresAt.Time.UTC()
		a.Expires = &v
	}
	return domain.MultipartUpload{ID: row.UploadID, Warehouse: row.Warehouse, Key: row.ObjectKey, Created: row.CreatedAt.UTC(), Attributes: a}
}
func (r *objectStore) CreateMultipart(ctx context.Context, upload domain.MultipartUpload, guard domain.PublicationGuard) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		a := upload.Attributes
		err := sqlcgen.New(tx).CreateTableMultipartUpload(ctx, sqlcgen.CreateTableMultipartUploadParams{Warehouse: upload.Warehouse, ObjectKey: upload.Key, UploadID: upload.ID, CreatedAt: upload.Created.UTC(), ContentType: a.ContentType, CacheControl: a.CacheControl, ContentDisposition: a.ContentDisposition, ContentEncoding: a.ContentEncoding, ContentLanguage: a.ContentLanguage, ExpiresAt: nullExpires(a.Expires), ChecksumAlgorithm: a.ChecksumAlgorithm})
		if err != nil {
			return err
		}
		return physicalGuard(ctx, guard)
	})
}
func getMultipartUpload(ctx context.Context, q *sqlcgen.Queries, warehouse, key, id string) (domain.MultipartUpload, error) {
	row, err := q.GetTableMultipartUpload(ctx, sqlcgen.GetTableMultipartUploadParams{Warehouse: warehouse, ObjectKey: key, UploadID: id})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.MultipartUpload{}, domain.NoSuchMultipartUpload()
	}
	return multipartUpload(row), err
}
func (r *objectStore) UploadMultipartPart(ctx context.Context, warehouse, key, id string, part domain.MultipartPart, data []byte, guard domain.PublicationGuard) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		if _, err := getMultipartUpload(ctx, q, warehouse, key, id); err != nil {
			return err
		}
		encrypted, err := s3tablescrypt.Seal(data, s3tablescrypt.PartIdentity(warehouse, key, id, int64(part.Number)))
		if err != nil {
			return err
		}
		err = q.PutTableMultipartPart(ctx, sqlcgen.PutTableMultipartPartParams{Warehouse: warehouse, ObjectKey: key, UploadID: id, PartNumber: int64(part.Number), Etag: part.ETag, Size: part.Size, ModifiedAt: part.Modified.UTC(), ChecksumCrc32: part.Checksums.CRC32, ChecksumCrc32c: part.Checksums.CRC32C, ChecksumCrc64nvme: part.Checksums.CRC64NVME, ChecksumSha1: part.Checksums.SHA1, ChecksumSha256: part.Checksums.SHA256, Content: encrypted.Data, EncryptionVersion: encrypted.Version, EncryptionAlgorithm: encrypted.Algorithm, EncryptionKey: encrypted.Key, EncryptionNonce: encrypted.Nonce})
		if err != nil {
			return err
		}
		return physicalGuard(ctx, guard)
	})
}
func (r *objectStore) ListMultipartParts(ctx context.Context, warehouse, key, id string) (domain.MultipartUpload, []domain.MultipartPart, error) {
	var upload domain.MultipartUpload
	var parts []domain.MultipartPart
	err := sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		var err error
		upload, err = getMultipartUpload(ctx, q, warehouse, key, id)
		if err != nil {
			return err
		}
		rows, err := q.ListTableMultipartParts(ctx, sqlcgen.ListTableMultipartPartsParams{Warehouse: warehouse, ObjectKey: key, UploadID: id})
		if err != nil {
			return err
		}
		parts = make([]domain.MultipartPart, len(rows))
		for i, row := range rows {
			parts[i] = domain.MultipartPart{Number: int(row.PartNumber), ETag: row.Etag, Size: row.Size, Modified: row.ModifiedAt.UTC(), Checksums: domain.ObjectChecksums{CRC32: row.ChecksumCrc32, CRC32C: row.ChecksumCrc32c, CRC64NVME: row.ChecksumCrc64nvme, SHA1: row.ChecksumSha1, SHA256: row.ChecksumSha256}}
		}
		return nil
	})
	return upload, parts, err
}
func (r *objectStore) CompleteMultipart(ctx context.Context, warehouse, key, id string, selected []domain.CompletedPart, modified time.Time, conditions domain.ObjectConditions, checksums domain.ObjectChecksums, guard domain.PublicationGuard) (domain.ObjectInfo, error) {
	var info domain.ObjectInfo
	err := sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		upload, err := getMultipartUpload(ctx, q, warehouse, key, id)
		if err != nil {
			return err
		}
		if err = domain.ValidateMultipartCompletionParts(selected); err != nil {
			return err
		}
		// Size the transient assembly using metadata only, then decrypt each selected
		// BLOB directly into its final position without retaining duplicate plaintext.
		metadata, err := q.ListTableMultipartParts(ctx, sqlcgen.ListTableMultipartPartsParams{Warehouse: warehouse, ObjectKey: key, UploadID: id})
		if err != nil {
			return err
		}
		var total int64
		index := 0
		// Both lists are ordered by part number; no second metadata map is needed.
		for _, part := range selected {
			for index < len(metadata) && metadata[index].PartNumber < int64(part.Number) {
				index++
			}
			if index == len(metadata) || metadata[index].PartNumber != int64(part.Number) {
				continue
			}
			size := metadata[index].Size
			if size < 0 || size > domain.MultipartMaximumPartSize || size > int64(int(^uint(0)>>1))-total {
				return s3tablescrypt.ErrEnvelope
			}
			total += size
		}
		data := make([]byte, 0, int(total))
		stored := make(map[int]domain.StoredMultipartPart, len(selected))
		for _, part := range selected {
			row, err := q.GetTableMultipartPart(ctx, sqlcgen.GetTableMultipartPartParams{Warehouse: warehouse, ObjectKey: key, UploadID: id, PartNumber: int64(part.Number)})
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			start := len(data)
			data, err = (s3tablescrypt.Envelope{Version: row.EncryptionVersion, Algorithm: row.EncryptionAlgorithm, Key: row.EncryptionKey, Nonce: row.EncryptionNonce, Data: row.Content}).Open(data, s3tablescrypt.PartIdentity(warehouse, key, id, int64(part.Number)), row.Size)
			if err != nil {
				return err
			}
			stored[part.Number] = domain.StoredMultipartPart{MultipartPart: domain.MultipartPart{Number: int(row.PartNumber), ETag: row.Etag, Size: row.Size, Modified: row.ModifiedAt.UTC(), Checksums: domain.ObjectChecksums{CRC32: row.ChecksumCrc32, CRC32C: row.ChecksumCrc32c, CRC64NVME: row.ChecksumCrc64nvme, SHA1: row.ChecksumSha1, SHA256: row.ChecksumSha256}}, Data: data[start:]}
		}
		assembled, err := domain.MultipartObjectInfo(upload, stored, selected, modified, checksums)
		if err != nil {
			return err
		}
		if err := domain.CheckMultipartCompletionConditions(assembled, conditions); err != nil {
			return err
		}
		exists, err := objectExists(ctx, q, warehouse, key)
		if err != nil {
			return err
		}
		// Keep checksum validation ahead of existence, without masking revocation.
		if err = physicalGuard(ctx, guard); err != nil {
			return err
		}
		if err = domain.CheckObjectConditions(exists, conditions); err != nil {
			return err
		}
		info = assembled
		if err = putObject(ctx, q, warehouse, data, info); err != nil {
			return err
		}
		if err = q.DeleteTableMultipartUpload(ctx, sqlcgen.DeleteTableMultipartUploadParams{Warehouse: warehouse, ObjectKey: key, UploadID: id}); err != nil {
			return err
		}
		return physicalGuard(ctx, guard)
	})
	return info, err
}
func (r *objectStore) AbortMultipart(ctx context.Context, warehouse, key, id string, guard domain.PublicationGuard) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		if _, err := getMultipartUpload(ctx, q, warehouse, key, id); err != nil {
			return err
		}
		if err := q.DeleteTableMultipartUpload(ctx, sqlcgen.DeleteTableMultipartUploadParams{Warehouse: warehouse, ObjectKey: key, UploadID: id}); err != nil {
			return err
		}
		return physicalGuard(ctx, guard)
	})
}

func (r *objectStore) GetMultipartUpload(ctx context.Context, warehouse, key, id string) (domain.MultipartUpload, error) {
	var upload domain.MultipartUpload
	err := sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		upload, err = getMultipartUpload(ctx, sqlcgen.New(tx), warehouse, key, id)
		return err
	})
	return upload, err
}
