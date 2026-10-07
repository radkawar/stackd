package apigatewayexec

import "context"

// ExecutionTarget binds a custom domain without changing the signed request URL.
type ExecutionTarget struct{ APIID, Stage, Path string }
type executionTargetKey struct{}

func WithExecutionTarget(ctx context.Context, target ExecutionTarget) context.Context {
	return context.WithValue(ctx, executionTargetKey{}, target)
}
func CustomExecutionTarget(ctx context.Context) (ExecutionTarget, bool) {
	v, ok := ctx.Value(executionTargetKey{}).(ExecutionTarget)
	return v, ok
}
