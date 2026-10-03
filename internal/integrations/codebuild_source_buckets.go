package integrations

import (
	"context"
	"errors"

	"stackd/internal/awsctx"
	"stackd/internal/services/s3"
)

// CodeBuildSourceBuckets exposes only partition-scoped existence to project
// admission. This is not a HeadBucket request or permission to read objects.
// S3's typed repository joins the current transaction without an external effect.
type CodeBuildSourceBuckets struct {
	Repository s3.Repository
}

func (a CodeBuildSourceBuckets) Exists(ctx context.Context, name string) (bool, error) {
	var exists bool
	err := a.Repository.View(ctx, func(reader s3.Reader) error {
		_, err := reader.Bucket(s3.BucketKey{Partition: awsctx.FromContext(ctx).Partition, Name: name})
		if errors.Is(err, s3.ErrNotFound) {
			return nil
		}
		exists = err == nil
		return err
	})
	return exists, err
}
