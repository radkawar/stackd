package lambda

import (
	"context"
	"errors"

	"stackd/internal/awswire"
)

type layerVersionOwnerContextKey struct{}

// WithLayerVersionOwner constrains trusted in-process publication and deletion
// commands to one owner. It does not authorize the caller or add native request
// fields. Incomplete identities fail closed.
func WithLayerVersionOwner(ctx context.Context, owner LayerVersionOwner) context.Context {
	return context.WithValue(ctx, layerVersionOwnerContextKey{}, owner)
}

func layerVersionOwnerFor(ctx context.Context) (LayerVersionOwner, *awswire.Error) {
	owner, present := ctx.Value(layerVersionOwnerContextKey{}).(LayerVersionOwner)
	if present && (owner.StackID == "" || owner.LogicalID == "" || owner.Token == "") {
		return LayerVersionOwner{}, failure("AccessDeniedException", "The layer version owner identity is incomplete.", 403)
	}
	return owner, nil
}

// Call inside the deletion transaction. Absence remains idempotent, but an
// extant native, legacy or differently owned publication is never adopted.
func requireLayerVersionOwner(r Reader, key LayerVersionKey) error {
	owner, wire := layerVersionOwnerFor(r.Context())
	if wire != nil {
		return wire
	}
	if owner == (LayerVersionOwner{}) {
		return nil
	}
	v, err := r.LayerVersion(key)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if v.Owner != owner {
		return failure("AccessDeniedException", "The layer version belongs to a different owner.", 403)
	}
	return nil
}
