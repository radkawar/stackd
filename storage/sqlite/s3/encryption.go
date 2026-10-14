package s3

import (
	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (w writer) ReplaceObjectEncryption(key domain.ObjectVersionKey, algorithm, arn string, wrapped []byte, encryptionContext map[string]string) error {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	count, err := w.q.ReplaceObjectVersionEncryption(w.ctx, sqlcgen.ReplaceObjectVersionEncryptionParams{
		EncryptionAlgorithm: algorithm, KmsKeyArn: arn,
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name, VersionID: key.VersionID,
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrNotFound
	}
	count, err = w.q.ReplaceObjectVersionEncryptionKey(w.ctx, sqlcgen.ReplaceObjectVersionEncryptionKeyParams{
		EncryptionKey: wrapped,
		Partition:     key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrNotFound
	}
	if err := w.q.DeleteObjectVersionEncryptionContext(w.ctx, sqlcgen.DeleteObjectVersionEncryptionContextParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
	}); err != nil {
		return err
	}
	for name, value := range encryptionContext {
		if err := w.q.PutObjectVersionEncryptionContext(w.ctx, sqlcgen.PutObjectVersionEncryptionContextParams{
			Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
			Key: name, Value: value,
		}); err != nil {
			return err
		}
	}
	return nil
}
