package opensearch

import "context"

type cloudFormationOwnerKey struct{}

// WithCloudFormationOwner binds one exact CloudFormation resource incarnation
// to domain commands from either the OpenSearch or the legacy ES frontend.
// CreateDomain persists the claim in the same transaction as the new domain.
// Every other command treats a domain carrying a different claim as absent,
// so a stale incarnation can neither observe nor mutate a same-name domain.
// The claim is controller-private and never crosses an AWS request or response.
func WithCloudFormationOwner(ctx context.Context, claim string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, claim)
}

func cloudFormationOwner(ctx context.Context) string {
	claim, _ := ctx.Value(cloudFormationOwnerKey{}).(string)
	return claim
}

// cloudFormationForeign reports whether a fenced command must not see v.
func cloudFormationForeign(ctx context.Context, v Domain) bool {
	claim := cloudFormationOwner(ctx)
	return claim != "" && v.Ownership != claim
}
