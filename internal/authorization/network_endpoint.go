package authorization

import (
	"context"
	"stackd/iam/policy"

	"stackd/internal/awswire"
)

// NetworkEndpointGuard is a trusted transport-owned policy intersection. It
// cannot grant IAM permission or be installed from an HTTP header. Context adds
// only EC2-authoritative network condition keys; Authorize runs after ordinary
// IAM/resource/Organizations grants, with the same resolved action and resource.
type NetworkEndpointGuard interface {
	Context(context.Context, Request) (map[string][]string, *awswire.Error)
	Authorize(context.Context, Request, policy.Principal) *awswire.Error
}

type networkEndpointGuardKey struct{}

func WithNetworkEndpointGuard(ctx context.Context, guard NetworkEndpointGuard) context.Context {
	return context.WithValue(ctx, networkEndpointGuardKey{}, guard)
}

func networkEndpointGuard(ctx context.Context) NetworkEndpointGuard {
	guard, _ := ctx.Value(networkEndpointGuardKey{}).(NetworkEndpointGuard)
	return guard
}

func authorizeNetworkEndpoint(ctx context.Context, request Request, principal policy.Principal) *awswire.Error {
	if guard := networkEndpointGuard(ctx); guard != nil {
		return guard.Authorize(ctx, request, principal)
	}
	return nil
}

type networkEndpointDisabled struct{}

// WithoutNetworkEndpointGuard is for the guard's trusted EC2 topology reads,
// preventing recursive endpoint evaluation of its own internal owner queries.
func WithoutNetworkEndpointGuard(ctx context.Context) context.Context {
	return context.WithValue(ctx, networkEndpointGuardKey{}, networkEndpointDisabled{})
}
