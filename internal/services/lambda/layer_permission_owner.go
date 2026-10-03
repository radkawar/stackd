package lambda

import (
	"context"
	"errors"

	"stackd/internal/awswire"
)

type layerPermissionOwnerContextKey struct{}

// WithLayerPermissionOwner enables exact deployment receipt recovery for trusted
// in-process permission creation. It neither authorizes a caller nor adds wire fields.
func WithLayerPermissionOwner(ctx context.Context, owner LayerPermissionOwner) context.Context {
	return context.WithValue(ctx, layerPermissionOwnerContextKey{}, owner)
}

func layerPermissionOwnerFor(ctx context.Context) (LayerPermissionOwner, *awswire.Error) {
	owner, present := ctx.Value(layerPermissionOwnerContextKey{}).(LayerPermissionOwner)
	if present && (owner.StackID == "" || owner.LogicalID == "" || owner.Token == "") {
		return LayerPermissionOwner{}, failure("AccessDeniedException", "The layer permission owner identity is incomplete.", 403)
	}
	return owner, nil
}

// Call only inside the mutation transaction, after current IAM authorization.
func requireLayerPermissionOwner(r LayerReader, key LayerPermissionKey, owner LayerPermissionOwner) error {
	stored, err := r.LayerPermissionOwner(key)
	if errors.Is(err, ErrNotFound) || (err == nil && stored != owner) {
		return failure("AccessDeniedException", "The layer permission belongs to a different owner.", 403)
	}
	return err
}
