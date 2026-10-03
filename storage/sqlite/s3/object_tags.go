package s3

import (
	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) ObjectTags(key domain.ObjectVersionKey) ([]domain.Tag, error) {
	rows, err := r.q.GetObjectTags(r.ctx, sqlcgen.GetObjectTagsParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Tag, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.Tag{Key: row.Key, Value: row.Value})
	}
	return out, nil
}

func (w writer) ReplaceObjectTags(key domain.ObjectVersionKey, tags []domain.Tag) error {
	if err := w.q.DeleteObjectTags(w.ctx, sqlcgen.DeleteObjectTagsParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
	}); err != nil {
		return err
	}
	for _, tag := range tags {
		if err := w.q.PutObjectTag(w.ctx, sqlcgen.PutObjectTagParams{
			Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID, Key: tag.Key, Value: tag.Value,
		}); err != nil {
			return err
		}
	}
	return nil
}
