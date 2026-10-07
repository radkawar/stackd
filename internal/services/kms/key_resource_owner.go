package kms

import (
	"context"

	"stackd/internal/awswire"
)

// KeyResourceOwner identifies a trusted consumer's regional key incarnation.
// Native requests do not carry this constraint and never acquire an old claim
// by recreating a related key with the same multi-Region key ID.
type KeyResourceOwner struct{ StackID, LogicalID, Token string }

type keyResourceOwnerContextKey struct{}

// WithKeyResourceOwner fences in-process key commands without replacing IAM
// authorization. The owner is stored on the regional KMS key, not in tags.
func WithKeyResourceOwner(ctx context.Context, owner KeyResourceOwner) context.Context {
	return context.WithValue(ctx, keyResourceOwnerContextKey{}, owner)
}

func keyResourceOwnerFor(ctx context.Context) (KeyResourceOwner, *awswire.Error) {
	owner, present := ctx.Value(keyResourceOwnerContextKey{}).(KeyResourceOwner)
	if present && (owner.StackID == "" || owner.LogicalID == "" || owner.Token == "") {
		return KeyResourceOwner{}, failure("AccessDeniedException", "The key resource owner identity is incomplete.")
	}
	return owner, nil
}

func withoutKeyResourceOwner(ctx context.Context) context.Context {
	return context.WithValue(ctx, keyResourceOwnerContextKey{}, nil)
}

func checkKeyResourceOwner(ctx context.Context, k *key) *awswire.Error {
	owner, err := keyResourceOwnerFor(ctx)
	if err != nil {
		return err
	}
	if owner != (KeyResourceOwner{}) && (k.owner != owner || keyScope(k) != scopeFor(ctx)) {
		return failure("AccessDeniedException", "The key belongs to a different resource incarnation.")
	}
	return nil
}
