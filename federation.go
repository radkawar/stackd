package stackd

import (
	"net/http"

	"stackd/clock"
	"stackd/internal/services/iam"
	"stackd/internal/services/sts"
)

// OIDCDiscovery is the replaceable issuer discovery boundary. Implementations
// validate metadata and public signing keys for the configured HTTPS issuer.
type OIDCDiscovery = iam.OIDCDiscovery

// OIDCDiscoveryRequest identifies a configured issuer and its TLS thumbprints.
// The issuer is taken from IAM configuration, never from a token-supplied URL.
type OIDCDiscoveryRequest = iam.OIDCDiscoveryRequest

// OIDCDiscoveryResult holds verified metadata, public keys and cache lifetime.
type OIDCDiscoveryResult = iam.OIDCDiscoveryResult

// OIDCSigningKey holds the public JWK fields needed to verify a signed token.
type OIDCSigningKey = iam.OIDCSigningKey

// NewHTTPOIDCDiscovery explicitly enables HTTPS issuer discovery through a
// cloned transport. A nil transport selects a clone of Go's default transport.
// Assign the returned source to Config.OIDCDiscovery to enable network access.
func NewHTTPOIDCDiscovery(transport *http.Transport) (OIDCDiscovery, error) {
	return iam.NewHTTPOIDCDiscovery(transport)
}

// NewHTTPOIDCDiscoveryWithClock measures cache lifetimes in the same service
// time as Config.Clock. TLS validation and HTTP deadlines retain real time.
func NewHTTPOIDCDiscoveryWithClock(transport *http.Transport, source clock.Clock) (OIDCDiscovery, error) {
	return iam.NewHTTPOIDCDiscoveryWithClock(transport, source)
}

// OAuthTokenSource verifies opaque social-provider tokens through an explicit dependency.
type OAuthTokenSource = sts.OAuthTokenSource

// OAuthIdentity carries the verified application and subject identifiers.
type OAuthIdentity = sts.OAuthIdentity

// OAuthHTTPConfig configures provider introspection and its HTTP dependency.
type OAuthHTTPConfig = sts.OAuthHTTPConfig

// NewHTTPOAuthTokenSource enables HTTPS introspection for configured social providers.
func NewHTTPOAuthTokenSource(config OAuthHTTPConfig) (OAuthTokenSource, error) {
	return sts.NewHTTPOAuthTokenSource(config)
}
