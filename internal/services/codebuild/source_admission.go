package codebuild

import (
	"context"

	api "stackd/internal/awsapi/codebuild"
)

// SourceBuckets reads bucket existence, not object or caller S3 authority. Native
// project admission accepts an existing bucket even when both caller and build
// role are denied S3 access; downloading still uses the current execution role.
// Implementations must join the caller's local transaction without external I/O.
type SourceBuckets interface {
	Exists(context.Context, string) (bool, error)
}

func (s *Service) validateSourceBuckets(ctx context.Context, primary *api.ProjectSource, secondaries api.ProjectSources) error {
	if primary != nil {
		if err := s.validateSourceBucket(ctx, *primary); err != nil {
			return err
		}
	}
	for _, source := range secondaries {
		if err := s.validateSourceBucket(ctx, source); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) validateSourceBucket(ctx context.Context, source api.ProjectSource) error {
	if value(source.Type) != "S3" {
		return nil
	}
	location := value(source.Location)
	bucket, _, err := sourceLocation(location)
	if err != nil {
		return err
	}
	if s.sourceBuckets == nil {
		return failure("InternalFailure", "S3 source bucket discovery is unavailable.")
	}
	exists, err := s.sourceBuckets.Exists(ctx, bucket)
	if err != nil {
		return err
	}
	if !exists {
		return failure("InvalidInputException", "Bucket "+location+" does not exist")
	}
	return nil
}
