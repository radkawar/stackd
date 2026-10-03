package iam

import "slices"

// OutboundWebIdentityRecord owns an account's stable public issuer and signing
// material. Disabling issuance retains the keys so existing tokens remain valid.
type OutboundWebIdentityRecord struct {
	// TODO: Comeback capture signing-key rotation/retention and remaining partition-specific outbound identity behavior before completing the federation audit.
	Enabled             Propagated[bool]
	IssuerID, IssuerURL string
	RS256, ES384        OutboundSigningKey
}

// OutboundSigningKey stores a signing key in PKCS#8 DER form. Public discovery
// exposes only its ID and derived public JWK material.
type OutboundSigningKey struct {
	ID       string
	PKCS8DER []byte `json:"-" xml:"-"`
}

func cloneOutboundWebIdentity(record *OutboundWebIdentityRecord) *OutboundWebIdentityRecord {
	if record == nil {
		return nil
	}
	copy := *record
	copy.RS256.PKCS8DER = slices.Clone(record.RS256.PKCS8DER)
	copy.ES384.PKCS8DER = slices.Clone(record.ES384.PKCS8DER)
	copy.Enabled = record.Enabled.clone()
	return &copy
}
