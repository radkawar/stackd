package sts

import (
	"context"
	"time"
)

// OIDCProviderSource reads detached IAM configuration and resolves public keys
// only through the issuer stored there. Key results must identify the exact
// provider incarnation and configuration version used during discovery.
type OIDCProviderSource interface {
	OIDCProviderForFederation(context.Context, string) (OIDCProviderSnapshot, error)
	ResolveOIDCSigningKeys(context.Context, string) (OIDCKeySet, error)
}

type OIDCProviderSnapshot struct {
	ARN, ID, Version, IssuerURL string
	ClientIDs, Thumbprints      []string
}
type OIDCKeySet struct {
	IssuerURL, ProviderID, ProviderVersion string
	SigningAlgorithms                      []string
	Keys                                   []OIDCSigningKey
	CacheUntil                             time.Time
}
