package lambda

import (
	"context"

	"stackd/internal/awswire"
)

// FunctionPolicyOwner identifies one trusted deployment create attempt.
// It enables create recovery only; it does not fence subsequent writes or deletes.
type FunctionPolicyOwner struct {
	StackID   string
	LogicalID string
	Token     string
}

// FunctionPolicyDeployment carries private full-policy deployment semantics.
type FunctionPolicyDeployment struct {
	Owner      FunctionPolicyOwner
	CreateOnly bool
}

type functionPolicyDeploymentContextKey struct{}

// WithFunctionPolicyDeployment does not grant authorization or change public API fields.
func WithFunctionPolicyDeployment(ctx context.Context, deployment FunctionPolicyDeployment) context.Context {
	return context.WithValue(ctx, functionPolicyDeploymentContextKey{}, deployment)
}

func functionPolicyDeploymentFor(ctx context.Context) (FunctionPolicyDeployment, *awswire.Error) {
	deployment, _ := ctx.Value(functionPolicyDeploymentContextKey{}).(FunctionPolicyDeployment)
	owner := deployment.Owner
	if owner != (FunctionPolicyOwner{}) && (owner.StackID == "" || owner.LogicalID == "" || owner.Token == "") {
		return FunctionPolicyDeployment{}, failure("AccessDeniedException", "The function policy owner identity is incomplete.", 403)
	}
	return deployment, nil
}
