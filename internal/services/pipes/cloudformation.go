package pipes

import (
	"context"
	api "stackd/internal/awsapi/pipes"
)

type CloudFormationConfiguration struct {
	Owner             string
	ReplaceSource     bool
	Source            *api.PipeSourceParameters
	ReplaceEnrichment bool
}
type cloudFormationConfigurationKey struct{}

// The adapter supplies admitted, typed desired configuration outside public
// request DTOs. Native partial-update semantics remain unchanged.
func WithCloudFormationConfiguration(ctx context.Context, v CloudFormationConfiguration) context.Context {
	return context.WithValue(ctx, cloudFormationConfigurationKey{}, v)
}
func cloudFormationConfiguration(ctx context.Context) CloudFormationConfiguration {
	v, _ := ctx.Value(cloudFormationConfigurationKey{}).(CloudFormationConfiguration)
	return v
}
func cloudFormationOwned(ctx context.Context, p PipeRecord) error {
	v := cloudFormationConfiguration(ctx)
	if v.Owner != "" && p.CFNOwner != v.Owner {
		return failure("ConflictException", "Pipe belongs to another CloudFormation incarnation.", 409)
	}
	return nil
}
