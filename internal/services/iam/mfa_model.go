package iam

import "time"

// MFADevice is a virtual TOTP device stored within the IAM transaction domain.
// Binding contains secret material; public list/get adapters must never expose it.
type MFADevice struct {
	CloudFormationOwner string
	SerialNumber        string
	Binding             Propagated[MFABinding]
	EnableDate          time.Time
	// RetiredAt hides a deleted device from IAM while its preceding binding
	// finishes propagating to STS and its verification budget expires.
	// Successful IAM requests reclaim expired rows.
	RetiredAt time.Time
	// LastPairStep is the second counter accepted by enrollment/resynchronization.
	// Subsequent pairs must both be newer, including after deactivation.
	LastPairStep *int64
	// UsedCodes covers current and still-visible preceding bindings. A new
	// device at the same ARN has independent codes because its seed differs.
	UsedCodes         []MFAUsedCode
	VerificationCount MFAVerificationCount
	Tags              []Tag
}

// MFABinding is the device configuration propagated from IAM to STS. Seed is
// immutable secret key material, represented as a string for value semantics.
type MFABinding struct {
	Seed      string
	UserID    string
	SkewSteps int64
}

// MFAUsedCode identifies a consumed counter for a particular virtual device key.
type MFAUsedCode struct {
	Seed string
	Step int64
}

// MFAVerificationCount is a device ARN's verification budget for one UTC window.
// Accepted and rejected codes count alike, including across seed replacements.
type MFAVerificationCount struct {
	Window time.Time
	Count  int
}
