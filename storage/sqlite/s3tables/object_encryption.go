package s3tables

import (
	"context"
	"database/sql"
	"errors"

	"stackd/storage/internal/s3tablescrypt"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/s3tables/internal/sqlcgen"
)

func openObject(row sqlcgen.S3tablesObject, warehouse, key string) ([]byte, error) {
	return (s3tablescrypt.Envelope{Version: row.EncryptionVersion, Algorithm: row.EncryptionAlgorithm, Key: row.EncryptionKey, Nonce: row.EncryptionNonce, Data: row.Content}).Open(nil, s3tablescrypt.ObjectIdentity(warehouse, key), row.Size)
}

// Migration reads one BLOB at a time. A malformed envelope or failed write rolls
// back every conversion, and callers receive no adapter until the commit succeeds.
func migrateObjectEncryption(ctx context.Context, db *sql.DB) error {
	return sqlite.Transact(ctx, db, false, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		for {
			row, err := q.NextTableWarehouseObjectEncryption(ctx)
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			if err != nil {
				return err
			}
			if int64(len(row.Content)) != row.Size {
				return s3tablescrypt.ErrEnvelope
			}
			e := s3tablescrypt.Envelope{Version: row.EncryptionVersion, Algorithm: row.EncryptionAlgorithm, Key: row.EncryptionKey, Nonce: row.EncryptionNonce, Data: row.Content}
			aad := s3tablescrypt.ObjectIdentity(row.Warehouse, row.ObjectKey)
			if e.Legacy() {
				e, err = s3tablescrypt.Seal(row.Content, aad)
				if err == nil {
					err = q.EncryptLegacyTableWarehouseObject(ctx, sqlcgen.EncryptLegacyTableWarehouseObjectParams{Warehouse: row.Warehouse, ObjectKey: row.ObjectKey, Content: e.Data, EncryptionVersion: e.Version, EncryptionAlgorithm: e.Algorithm, EncryptionKey: e.Key, EncryptionNonce: e.Nonce})
				}
			} else {
				return s3tablescrypt.ErrEnvelope
			}
			if err != nil {
				return err
			}
		}
		for {
			row, err := q.NextTableMultipartPartEncryption(ctx)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			if int64(len(row.Content)) != row.Size {
				return s3tablescrypt.ErrEnvelope
			}
			e := s3tablescrypt.Envelope{Version: row.EncryptionVersion, Algorithm: row.EncryptionAlgorithm, Key: row.EncryptionKey, Nonce: row.EncryptionNonce, Data: row.Content}
			aad := s3tablescrypt.PartIdentity(row.Warehouse, row.ObjectKey, row.UploadID, row.PartNumber)
			if e.Legacy() {
				e, err = s3tablescrypt.Seal(row.Content, aad)
				if err == nil {
					err = q.EncryptLegacyTableMultipartPart(ctx, sqlcgen.EncryptLegacyTableMultipartPartParams{Warehouse: row.Warehouse, ObjectKey: row.ObjectKey, UploadID: row.UploadID, PartNumber: row.PartNumber, Content: e.Data, EncryptionVersion: e.Version, EncryptionAlgorithm: e.Algorithm, EncryptionKey: e.Key, EncryptionNonce: e.Nonce})
				}
			} else {
				return s3tablescrypt.ErrEnvelope
			}
			if err != nil {
				return err
			}
		}
	})
}
