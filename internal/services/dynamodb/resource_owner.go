package dynamodb

import (
	"context"
	"errors"
)

// ResourceOwner is a trusted controller claim on a native table incarnation.
// Public tags and native request payloads cannot set or change this claim.
type ResourceOwner struct{ StackID, LogicalID, Token string }
type resourceOwnerKey struct{}
type resourceOwnerConstraint struct {
	Owner  ResourceOwner
	Create bool
}

func WithResourceOwner(ctx context.Context, owner ResourceOwner, create bool) context.Context {
	return context.WithValue(ctx, resourceOwnerKey{}, resourceOwnerConstraint{owner, create})
}

func resourceOwnerFor(ctx context.Context) (ResourceOwner, error) {
	c, present := ctx.Value(resourceOwnerKey{}).(resourceOwnerConstraint)
	if present && (c.Owner.StackID == "" || c.Owner.LogicalID == "" || c.Owner.Token == "") {
		return ResourceOwner{}, failure("AccessDeniedException", "Incomplete table resource owner")
	}
	return c.Owner, nil
}

func checkResourceOwner(ctx context.Context, r Reader, key TableKey) error {
	owner, err := resourceOwnerFor(ctx)
	if err != nil || owner == (ResourceOwner{}) {
		return err
	}
	table, err := r.Table(key)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if table.Owner != owner || key.Scope != scopeFor(ctx) {
		c, _ := ctx.Value(resourceOwnerKey{}).(resourceOwnerConstraint)
		if c.Create {
			return failure("AlreadyExistsException", "The table belongs to a different resource incarnation")
		}
		return failure("AccessDeniedException", "The table belongs to a different resource incarnation")
	}
	return nil
}
