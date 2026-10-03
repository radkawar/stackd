package sts

import (
	"context"
	"time"
)

// OAuthTokenSource validates opaque access tokens against an explicitly
// configured provider. Token input cannot select an endpoint or verification key.
type OAuthTokenSource interface {
	VerifyOAuthAccessToken(context.Context, string, string) (OAuthIdentity, error)
}

// OAuthIdentity contains only provider-verified app/user identifiers. The role
// trust policy must permit the selected provider and any audience constraints.
type OAuthIdentity struct {
	ProviderID, Subject, Audience string
	TrustContext, SessionContext  map[string][]string
	// ExpiresAt is the exclusive provider-verified token deadline. Nil means
	// the provider supplied no expiry, as for Facebook's zero expiry sentinel.
	ExpiresAt *time.Time
}
