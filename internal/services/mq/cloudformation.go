package mq

import "context"

type cloudFormationOwnerKey struct{}
type cloudFormationOwner struct{ Kind, Claim string }

const (
	cloudFormationBroker        = "Broker"
	cloudFormationConfiguration = "Configuration"
)

// WithCloudFormationBrokerOwner binds one exact CloudFormation incarnation to
// broker commands. CreateBroker persists the claim in its admission
// transaction; every other broker command, including CreatorRequestId replay,
// treats a broker carrying another claim as absent or conflicting.
func WithCloudFormationBrokerOwner(ctx context.Context, claim string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{cloudFormationBroker, claim})
}

// WithCloudFormationConfigurationOwner is the configuration equivalent of
// WithCloudFormationBrokerOwner. Configuration names are not unique, so the
// private claim, never a name or public tag, identifies the incarnation.
func WithCloudFormationConfigurationOwner(ctx context.Context, claim string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{cloudFormationConfiguration, claim})
}

func cloudFormationClaim(ctx context.Context, kind string) (string, bool) {
	owner, ok := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	return owner.Claim, ok && owner.Kind == kind
}

// cloudFormationForeign reports whether a fenced command of kind must not see
// a row carrying ownership. An empty fenced claim never matches an unowned row.
func cloudFormationForeign(ctx context.Context, kind, ownership string) bool {
	claim, ok := cloudFormationClaim(ctx, kind)
	return ok && (claim == "" || ownership != claim)
}
