package cloudtrail

import (
	"context"

	"stackd/internal/awswire"
)

type cloudFormationOwnerKey struct{}
type cloudFormationOwner struct {
	Marker string
	Create bool
}

// WithCloudFormationOwner fences trusted commands against the private claim on
// the actual trail, including the post-destination-validation commit recheck.
func WithCloudFormationOwner(ctx context.Context, marker string, create bool) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{Marker: marker, Create: create})
}

func cloudFormationClaim(ctx context.Context, current string, exists bool) (string, *awswire.Error) {
	owner, ok := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	if !ok {
		return current, nil
	}
	if owner.Marker == "" || exists && current != owner.Marker || !exists && !owner.Create {
		return "", failure("AccessDeniedException", "The trail belongs to a different CloudFormation incarnation.")
	}
	return owner.Marker, nil
}

func cloudFormationOwned(ctx context.Context, current string) *awswire.Error {
	_, wire := cloudFormationClaim(ctx, current, true)
	return wire
}
