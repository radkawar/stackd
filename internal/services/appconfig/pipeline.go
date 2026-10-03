package appconfig

import "context"

type pipelineActionContextKey struct{}

// WithPipelineAction identifies the trusted producer of a StartDeployment call.
// It lets controller recovery find the accepted deployment without making public
// StartDeployment idempotent or requiring extra ListDeployments permissions.
func WithPipelineAction(ctx context.Context, actionID string) context.Context {
	return context.WithValue(ctx, pipelineActionContextKey{}, actionID)
}

func pipelineActionID(ctx context.Context) string {
	id, _ := ctx.Value(pipelineActionContextKey{}).(string)
	return id
}
