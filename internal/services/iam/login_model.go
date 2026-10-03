package iam

import (
	"context"
	"errors"
	"time"

	"stackd/internal/identity"
)

// PasswordDigest is a versioned, salted password verifier. Plaintext passwords
// never cross the repository boundary.
type PasswordDigest struct {
	Algorithm  string
	Iterations int
	Salt       []byte
	Hash       []byte
}

// LoginProfileRecord is keyed by the immutable IAM user ID, so user renames do
// not lose credentials or associate a deleted user's password with a new user.
type LoginProfileRecord struct {
	UserID                string
	CreateDate            time.Time
	PasswordChangedAt     time.Time
	PasswordResetRequired bool
	Password              PasswordDigest
	PreviousPasswords     []PasswordDigest
}

// AccountPasswordPolicy is the custom policy. A nil policy means AWS defaults;
// it is distinct from a custom policy with no composition requirements.
type AccountPasswordPolicy struct {
	MinimumPasswordLength      int
	RequireSymbols             bool
	RequireNumbers             bool
	RequireUppercaseCharacters bool
	RequireLowercaseCharacters bool
	AllowUsersToChangePassword bool
	MaxPasswordAge             int
	PasswordReusePrevention    int
	HardExpiry                 bool
}

// AccountSettingsRecord contains IAM-owned account-wide settings.
type AccountSettingsRecord struct {
	Alias               string
	PasswordPolicy      *AccountPasswordPolicy
	RootLoginProfile    *RootLoginProfileRecord
	OutboundWebIdentity *OutboundWebIdentityRecord
	RoleManagerEnabled  bool
	// GlobalEndpointAllRegions selects STS v2 session tokens. The default is v1.
	GlobalEndpointAllRegions Propagated[bool]
}

// RootLoginProfileRecord represents root password recovery enabled through an
// AssumeRoot CreateLoginProfile request. That API accepts no password: root
// password recovery occurs through the account email, outside IAM user sign-in.
type RootLoginProfileRecord struct {
	CreateDate time.Time
}

var ErrInvalidPassword = errors.New("invalid IAM user password")

// PasswordAuthentication reports password verification, not permission to issue
// a session. A sign-in consumer must complete MFA and every required password
// change before it issues credentials. Hard expiry requires an administrator in
// console sign-in; the signed ChangePassword API remains available.
type PasswordAuthentication struct {
	Principal                  identity.Principal
	PasswordChangeRequired     bool
	PasswordExpired            bool
	AdministratorResetRequired bool
	PasswordExpiresAt          *time.Time
}

// PasswordVerifier is the credential-verification boundary consumed by sign-in.
type PasswordVerifier interface {
	VerifyPassword(context.Context, Scope, string, string) (PasswordAuthentication, error)
}
