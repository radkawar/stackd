package s3

import (
	"context"

	"stackd/internal/awswire"
)

// CloudFormation ownership is private native-row provenance. A trusted
// CloudFormation or Cloud Control controller binds one exact resource
// incarnation claim to ordinary commands, which still evaluate current IAM.
// Claims are never wire input, never tags and never appear in a response.
type cloudFormationOwnerKey struct{ kind string }

const (
	cloudFormationBucket       = "Bucket"
	cloudFormationBucketPolicy = "BucketPolicy"
	cloudFormationAccessPoint  = "AccessPoint"
)

// WithCloudFormationBucketOwner binds an AWS::S3::Bucket incarnation claim.
// CreateBucket records it on a new bucket, or returns the bucket this claim
// already created without changing it; every other bucket command requires
// the stored claim in the same transaction as its effect.
func WithCloudFormationBucketOwner(ctx context.Context, claim string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{cloudFormationBucket}, claim)
}

// WithCloudFormationBucketPolicyOwner binds an AWS::S3::BucketPolicy
// incarnation claim. PutBucketPolicy attaches a policy only to a bucket with no
// policy or with this claim's policy; DeleteBucketPolicy removes only this
// claim's policy and reports NoSuchBucketPolicy when the claim has none.
func WithCloudFormationBucketPolicyOwner(ctx context.Context, claim string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{cloudFormationBucketPolicy}, claim)
}

// WithCloudFormationAccessPointOwner binds an AWS::S3::AccessPoint incarnation
// claim. CreateAccessPoint records it or returns this claim's access point, and
// every other access point command requires the stored claim.
func WithCloudFormationAccessPointOwner(ctx context.Context, claim string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{cloudFormationAccessPoint}, claim)
}

func cloudFormationOwner(ctx context.Context, kind string) (string, bool) {
	claim, _ := ctx.Value(cloudFormationOwnerKey{kind}).(string)
	return claim, claim != ""
}

func cloudFormationOwnerConflict(resource string) *awswire.Error {
	return failure("AccessDenied", "The "+resource+" belongs to a different CloudFormation resource incarnation.", 403)
}

// checkBucketOwner fences bucket commands bound to a bucket claim.
func checkBucketOwner(ctx context.Context, b BucketRecord) *awswire.Error {
	if claim, claimed := cloudFormationOwner(ctx, cloudFormationBucket); claimed && b.CloudFormationOwner != claim {
		return cloudFormationOwnerConflict("bucket")
	}
	return nil
}

// checkAccessPointOwner fences access point commands bound to a claim.
func checkAccessPointOwner(ctx context.Context, point AccessPointRecord) *awswire.Error {
	if claim, claimed := cloudFormationOwner(ctx, cloudFormationAccessPoint); claimed && point.CloudFormationOwner != claim {
		return cloudFormationOwnerConflict("access point")
	}
	return nil
}
