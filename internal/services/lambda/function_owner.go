package lambda

import (
	"context"
	"stackd/internal/awswire"
)

// FunctionOwner fences trusted CFN commands against deletion/recreation of the
// same public function name. Customer tags cannot claim this private identity.
type FunctionOwner struct{ StackID, LogicalID, Token string }
type functionOwnerContextKey struct{}

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
