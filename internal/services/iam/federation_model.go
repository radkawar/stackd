package iam

import (
	"context"
	"time"
)

// OIDCProviderRecord is account-global provider configuration. ID changes when
// an ARN is deleted and recreated, allowing consumers to detect stale snapshots.
type OIDCProviderRecord struct {
	ARN         string
	ID          string
	URL         string
	CreatedAt   time.Time
	ClientIDs   []string
	Thumbprints []string
	Tags        []Tag
}

// SAMLPrivateKeyRecord stores a provider assertion-decryption key in canonical
// PKCS#8 DER form. Public IAM responses expose only ID and CreatedAt.
type SAMLPrivateKeyRecord struct {
	ID        string
	CreatedAt time.Time
	PKCS8DER  []byte `json:"-" xml:"-"`
}

// SAMLProviderRecord keeps the original metadata plus its validated trust data.
// Certificate DER bytes and private key material never alias repository state.
type SAMLProviderRecord struct {
	ARN                     string
	Name                    string
	UUID                    string
	MetadataDocument        string
	CreatedAt               time.Time
	ValidUntil              time.Time
	Issuers                 []SAMLIssuerRecord
	AssertionEncryptionMode string
	PrivateKeys             []SAMLPrivateKeyRecord
	Tags                    []Tag
}

// SAMLIssuerRecord binds each metadata entity's signing certificates to its
// own issuer. Encryption-only certificates cannot authenticate assertions.
type SAMLIssuerRecord struct {
	EntityID            string
	SigningCertificates [][]byte
}

// OIDCDiscoveryRequest binds network discovery to an explicitly configured
// provider. Token-supplied discovery/JWK URLs must never enter this boundary.
type OIDCDiscoveryRequest struct {
	IssuerURL   string
	Thumbprints []string
}

// OIDCSigningKey is the public JWK material consumed by STS verification.
type OIDCSigningKey struct {
	ID           string
	Type         string
	Use          string
	Algorithm    string
	N            string
	E            string
	Curve        string
	X            string
	Y            string
	Certificates [][]byte
	Operations   []string
}

// OIDCDiscoveryResult contains verified issuer metadata and public signing keys.
// Thumbprints describe the TLS certificate chains observed for the configured
// discovery document and its advertised JWKS endpoint.
type OIDCDiscoveryResult struct {
	IssuerURL         string
	JWKSURL           string
	SigningAlgorithms []string
	SigningKeys       []OIDCSigningKey
	Thumbprints       []string
	CacheUntil        time.Time
}

// OIDCDiscovery is the replaceable network boundary for provider metadata. A
// nil implementation never falls back to the internet; tests inject a source.
type OIDCDiscovery interface {
	Discover(context.Context, OIDCDiscoveryRequest) (OIDCDiscoveryResult, error)
}
