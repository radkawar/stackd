package integrations

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/internal/services/s3"
)

// S3ReplicationRoles obtains ordinary IAM sessions through the shared service
// role owner; replication does not bypass role trust or create a second cache.
type S3ReplicationRoles struct {
	Roles    ServiceRoles
	sessions serviceRoleSessions
}

func (a *S3ReplicationRoles) Context(ctx context.Context, bucket s3.BucketRecord, roleARN string) (context.Context, error) {
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = bucket.Key.Partition, bucket.AccountID, bucket.Region
	ctx = awsctx.WithMetadata(ctx, metadata)
	return a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{
		Name: "s3.amazonaws.com", SourceARN: bucket.Key.ARN(), Type: "AWSService",
	}, roleARN, "s3-replication", "")
}
