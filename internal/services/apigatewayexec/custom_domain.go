package apigatewayexec

import "context"

// ExecutionTarget binds an owned host without changing the signed request URL.
type ExecutionTarget struct {
	APIID, Stage, Path string
	// DefaultEndpoint retains execute-api endpoint disablement and distinguishes
	// resource hosts from custom-domain mappings.
	DefaultEndpoint bool
	REST            bool
}
type executionTargetKey struct{}

func WithExecutionTarget(ctx context.Context, target ExecutionTarget) context.Context {
	return context.WithValue(ctx, executionTargetKey{}, target)
}
func CustomExecutionTarget(ctx context.Context) (ExecutionTarget, bool) {
	v, ok := ctx.Value(executionTargetKey{}).(ExecutionTarget)
	return v, ok
}
