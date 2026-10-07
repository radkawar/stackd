package xray

import (
	"context"
	"stackd/internal/awswire"
)

type cloudFormationOwnerKey struct{}
type cloudFormationOwner struct {
	Marker  string
	Create  bool
	Recover bool
}

func WithCloudFormationOwner(ctx context.Context, marker string, create bool) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{Marker: marker, Create: create})
}

// WithCloudFormationRecovery makes native creation an exact-claim observation.
// It never admits or mutates a row, and still checks the caller's current IAM.
func WithCloudFormationRecovery(ctx context.Context, marker string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{Marker: marker, Create: true, Recover: true})
}
func cloudFormationRecovering(ctx context.Context) bool {
	owner, _ := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	return owner.Recover
}
func cloudFormationClaim(ctx context.Context, old string, exists bool) (string, error) {
	owner, ok := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	if !ok {
		return old, nil
	}
	if owner.Marker == "" || exists && old != owner.Marker || !exists && !owner.Create {
		return "", &awswire.Error{Code: "AccessDeniedException", Message: "The resource belongs to a different CloudFormation incarnation.", StatusCode: 403}
	}
	return owner.Marker, nil
}
