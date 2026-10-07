package cognitoidentity

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/cognitoidentity"
)

// ResourceOwner identifies one CloudFormation logical resource incarnation.
// It is a typed private field of the pool row, never a customer-visible tag:
// public pool tags are mutable by TagResource and cannot prove ownership.
type ResourceOwner struct{ StackID, LogicalID, Token string }

type resourceOwnerKey struct{}

type creationRecoveryKey struct{}

// WithResourceOwner fences identity pool mutations to the incarnation that
// created the pool and recovers its create from the persisted claim.
func WithResourceOwner(ctx context.Context, owner ResourceOwner) context.Context {
	return context.WithValue(ctx, resourceOwnerKey{}, owner)
}

// WithCreationRecovery observes a create of this exact incarnation without
// performing it: the create command replays the claimed pool under the
// caller's current create authority, or fails ResourceNotFoundException when
// the incarnation was never admitted.
func WithCreationRecovery(ctx context.Context, owner ResourceOwner) context.Context {
	return context.WithValue(WithResourceOwner(ctx, owner), creationRecoveryKey{}, true)
}

func boundOwner(ctx context.Context) (ResourceOwner, bool) {
	owner, ok := ctx.Value(resourceOwnerKey{}).(ResourceOwner)
	return owner, ok
}

// ownedCommand runs inside the command transaction before the operation. A
// non-nil replay is this incarnation's persisted create result. Create records
// the bound owner on the new row itself; deletion removes it with the row.
func (s *Service) ownedCommand(tx Transaction, action string, in any) (any, error) {
	owner, bound := boundOwner(tx.Context())
	if !bound {
		return nil, nil
	}
	if owner.StackID == "" || owner.LogicalID == "" || owner.Token == "" {
		return nil, failure("InvalidParameterException", "Incomplete CloudFormation resource owner.")
	}
	require := func(id string) error {
		p, err := s.adminPool(tx, action, id)
		if err != nil {
			return err
		}
		if p.Owner != owner {
			return failure("ResourceConflictException", "The identity pool belongs to another CloudFormation resource incarnation.")
		}
		return nil
	}
	switch in := in.(type) {
	case *api.CreateIdentityPoolInput:
		// Replay and recovery need the same authority as the create itself.
		if err := s.authorize(tx, "cognito-identity:CreateIdentityPool", "*", createConditions(in)); err != nil {
			return nil, err
		}
		p, err := tx.PoolByOwner(scopeFor(tx.Context()), owner)
		if err == nil {
			notePool(tx.Context(), p.Key)
			return poolOutput(p), nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if recovering, _ := tx.Context().Value(creationRecoveryKey{}).(bool); recovering {
			return nil, failure("ResourceNotFoundException", "This exact CloudFormation resource incarnation was not admitted.")
		}
	case *api.UpdateIdentityPoolInput:
		return nil, require(value(in.IdentityPoolId))
	case *api.DeleteIdentityPoolInput:
		return nil, require(value(in.IdentityPoolId))
	}
	return nil, nil
}
