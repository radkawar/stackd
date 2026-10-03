package s3

import (
	"context"

	"stackd/internal/awswire"
)

func (s *Service) replicationReadPermission(ctx context.Context, c *apiCall, bucket BucketRecord, object ObjectRecord, conditions map[string][]string) *awswire.Error {
	wire := s.authorizeObject(ctx, c, bucket, object, "GetObjectVersionForReplication", conditions)
	if wire == nil || object.EncryptionAlgorithm == "aws:kms" {
		return wire
	}
	// These are independent alternatives for SSE-S3, including when one has
	// an explicit denial. KMS-encrypted objects require the replication action.
	return s.authorizeObject(ctx, c, bucket, object, "GetObjectVersion", conditions)
}

func (s *Service) replicationTagPermission(ctx context.Context, c *apiCall, bucket BucketRecord, key string, conditions map[string][]string) *awswire.Error {
	if wire := s.authorize(ctx, c, bucket, "ReplicateTags", key, conditions); wire == nil {
		return nil
	}
	// ReplicateObject covers tags without a separate grant, including boundary
	// ceilings. Explicit ReplicateTags denials in any applicable policy still
	// win; an early implicit denial from a separate evaluation cannot prove
	// that later policy layers contain no explicit denial.
	return s.authorizeACL(ctx, c, bucket, "ReplicateObject", key, conditions, nil, []string{"s3:ReplicateTags"})
}
