package identitystore

import (
	"context"
	"stackd/internal/awswire"
)

type cloudFormationOwnerKey struct{}

// WithCloudFormationOwner carries trusted controller provenance, not caller wire input.
// The owner stores it on the actual directory or assignment resource.
func WithCloudFormationOwner(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, owner)
}
func CloudFormationOwner(ctx context.Context) string {
	owner, _ := ctx.Value(cloudFormationOwnerKey{}).(string)
	return owner
}
func CheckCloudFormationOwner(ctx context.Context, stored string) error {
	if owner := CloudFormationOwner(ctx); owner != "" && owner != stored {
		return &awswire.Error{Code: "AccessDeniedException", Message: "resource is not owned by this CloudFormation incarnation", StatusCode: 403}
	}
	return nil
}
