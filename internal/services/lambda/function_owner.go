package lambda

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

// FunctionOwner fences trusted CFN commands against deletion/recreation of the
// same public function name. Customer tags cannot claim this private identity.
type FunctionOwner struct{ StackID, LogicalID, Token string }
type functionOwnerContextKey struct{}
type functionCreationRecoveryContextKey struct{}

// WithFunctionCreationRecovery observes an exact private admission without
// creating a function. Even an absence certificate requires current read IAM.
func WithFunctionCreationRecovery(ctx context.Context, owner FunctionOwner) context.Context {
	return context.WithValue(WithFunctionOwner(ctx, owner), functionCreationRecoveryContextKey{}, true)
}

func WithFunctionOwner(ctx context.Context, owner FunctionOwner) context.Context {
	return context.WithValue(ctx, functionOwnerContextKey{}, owner)
}
func functionOwnerFor(ctx context.Context) (FunctionOwner, *awswire.Error) {
	owner, present := ctx.Value(functionOwnerContextKey{}).(FunctionOwner)
	if present && (owner.StackID == "" || owner.LogicalID == "" || owner.Token == "") {
		return FunctionOwner{}, failure("AccessDeniedException", "The Lambda function owner identity is incomplete.", 403)
	}
	return owner, nil
}
func requireFunctionOwner(ctx context.Context, current FunctionOwner) *awswire.Error {
	owner, wire := functionOwnerFor(ctx)
	if wire != nil {
		return wire
	}
	if owner != (FunctionOwner{}) && owner != current {
		return failure("AccessDeniedException", "The Lambda function belongs to a different resource incarnation.", 403)
	}
	return nil
}

func (s *Service) recoverFunctionCreation(ctx context.Context, name string) (*api.GetFunctionConfigurationOutput, *awswire.Error) {
	owner, wire := functionOwnerFor(ctx)
	if wire != nil {
		return nil, wire
	}
	if owner == (FunctionOwner{}) {
		return nil, failure("AccessDeniedException", "The Lambda function owner identity is required.", 403)
	}
	var record FunctionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.Functions(scopeFor(ctx))
		if err != nil {
			return err
		}
		for _, current := range rows {
			if current.Owner != owner {
				continue
			}
			ref := FunctionReference{FunctionKey: current.Key}
			if wire := s.authorizeFunction(r, "GetFunctionConfiguration", ref, current, nil); wire != nil {
				return wire
			}
			record = current
			if pending, err := r.PendingFunction(current.Key); err == nil {
				if pending.Owner != owner {
					return failure("AccessDeniedException", "The pending Lambda function belongs to a different resource incarnation.", 403)
				}
				record = pending
			} else if !errors.Is(err, ErrNotFound) {
				return err
			}
			return nil
		}
		// An ordinary same-name object is not a receipt. Preserve its native
		// ownership error rather than interpreting copied public tags as a claim.
		for _, current := range rows {
			if current.Key.Name == name {
				if wire := s.authorizeFunction(r, "GetFunctionConfiguration", FunctionReference{FunctionKey: current.Key}, current, nil); wire != nil {
					return wire
				}
				return requireFunctionOwner(ctx, current.Owner)
			}
		}
		// Rejected names and other create properties must not be revalidated.
		key := FunctionKey{Scope: scopeFor(ctx), Name: name}
		if wire := s.authorize(r.Context(), "GetFunctionConfiguration", key.ARN(), nil, nil, nil); wire != nil {
			return wire
		}
		return ErrNotFound
	})
	if err != nil {
		return nil, wireError(err)
	}
	return configuration(record), nil
}
