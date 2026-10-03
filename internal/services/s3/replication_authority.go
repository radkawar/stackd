package s3

import "context"

// ReplicationRoles supplies a trust-authorized S3 execution session. Source
// ownership provides the trust context; current object and key permissions are
// evaluated by their owning services when the retained work runs.
type ReplicationRoles interface {
	Context(context.Context, BucketRecord, string) (context.Context, error)
}
