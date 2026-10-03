package sts

import (
	"context"
	"time"
)

// SAMLProviderSource supplies detached trust material from the requested IAM
// provider. Assertion-provided certificates and URLs never enter this source.
type SAMLProviderSource interface {
	SAMLProviderForFederation(context.Context, string) (SAMLProviderSnapshot, error)
}

// SAMLProviderSnapshot binds issuer certificates and decryption keys to one
// immutable provider incarnation and configuration version. AWS reports
// ValidUntil but does not use metadata/certificate expiry for authentication.
type SAMLProviderSnapshot struct {
	ARN, ID, Version, AssertionEncryptionMode string
	ValidUntil                                time.Time
	Issuers                                   []SAMLIssuerSnapshot
	PrivateKeys                               []SAMLDecryptionKey
}

type SAMLIssuerSnapshot struct {
	EntityID            string
	SigningCertificates [][]byte
}

// SAMLDecryptionKey contains canonical PKCS#8 DER, ordered oldest to newest in
// SAMLProviderSnapshot. It must never be included in API responses or logs.
type SAMLDecryptionKey struct {
	ID       string
	PKCS8DER []byte
}
