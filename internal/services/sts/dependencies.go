package sts

import (
	"context"
	"errors"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/identity"
)

// ErrFederationProviderNotFound is returned by configured federation sources
// when the requested provider no longer exists in its account and partition.
var ErrFederationProviderNotFound = errors.New("federation provider not found")

// ErrMFAUnavailable identifies an unassociated, missing or temporarily blocked
// MFA device. It is an authentication denial, distinct from a storage failure.
var ErrMFAUnavailable = errors.New("MFA device is unavailable")

// CredentialStore owns credential persistence and atomic issuance. STS owns
// request validation, trust evaluation and the permissions of issued sessions.
type CredentialStore interface {
	Resolve(context.Context, string) (identity.Credential, error)
	IssueSession(context.Context, identity.Credential, identity.SessionSpec) (identity.Credential, error)
	IssueRoleSession(context.Context, identity.Credential, identity.RoleSessionSpec) (identity.Credential, error)
	IssueRootSession(context.Context, identity.Credential, identity.RootSessionSpec) (identity.Credential, error)
	IssueFederation(context.Context, identity.Credential, identity.FederationSpec) (identity.Credential, error)
	AccessKeyAccount(context.Context, string) (string, error)
}

type RoleSnapshot struct {
	ARN, ID, Name, TrustPolicy string
	TrustPrincipalIDs          map[string]string
	MaxSessionDuration         time.Duration
	Tags                       map[string]string
	EvaluationTime             *time.Time
	ServiceLinkedRole          bool
}

// RoleSource returns detached current IAM role and policy data. Session managed
// policies resolve in the role account; the caller may be in another account.
type RoleSource interface {
	RoleForAssumption(context.Context, string) (RoleSnapshot, error)
	ResolveManagedPolicyDocuments(context.Context, []string) ([]string, error)
}

// RootSessionSource checks current organization membership, IAM trusted access,
// enabled features for the task, caller management/delegated authority and target state.
// Its detached Organizations snapshot is separate from IAM's issuance transaction.
type RootSessionSource interface {
	CheckRootSession(context.Context, string, string) error
}

// MFAVerifier validates caller ownership and consumes a TOTP counter in the
// session authority transaction before returning its authenticated time.
// Invalid codes return an awswire InvalidAuthenticationCode error; missing,
// unassociated or limited devices return ErrMFAUnavailable. These denials may
// commit authentication-attempt state without issuing credentials. Other errors
// are failures and roll back the authority transaction.
type MFAVerifier interface {
	VerifyMFA(context.Context, string, string) (time.Time, error)
}

// OutboundWebIdentityIssuer signs tokens using the account's current outbound
// federation configuration. Signing borrows the signed-session transaction;
// the issuer supplies authoritative iss and preserves the caller's claims.
type OutboundWebIdentityIssuer interface {
	SignWebIdentityToken(context.Context, string, map[string]any) (string, error)
	IsOutboundWebIdentityIssuer(context.Context, string) (bool, error)
}

type Dependencies struct {
	Credentials         CredentialStore
	Roles               RoleSource
	Authorizer          authorization.Authorizer
	MFA                 MFAVerifier
	OIDCProviders       OIDCProviderSource
	SAMLProviders       SAMLProviderSource
	OAuthTokens         OAuthTokenSource
	Federation          FederationAuthority
	Sessions            SessionAuthority
	RootSessions        RootSessionSource
	OutboundWebIdentity OutboundWebIdentityIssuer
	Identity            authorization.IdentitySource
	Organizations       authorization.OrganizationSource
	TokenPreferences    TokenPreferences
	Regions             RegionAccess
	Clock               clock.Clock
	APIEvents           apievents.Recorder
}

func NewWithDependencies(d Dependencies) *Service {
	if d.Credentials == nil {
		panic("sts: nil credential store")
	}
	if d.Clock == nil {
		d.Clock = clock.Real{}
	}
	if d.Authorizer == nil {
		d.Authorizer = authorization.NewWithClock(nil, nil, d.Clock)
	}
	return &Service{credentials: d.Credentials, roles: d.Roles, authorizer: d.Authorizer, mfa: d.MFA, oidcProviders: d.OIDCProviders, samlProviders: d.SAMLProviders, oauthTokens: d.OAuthTokens, federation: d.Federation, sessions: d.Sessions, rootSessions: d.RootSessions, outboundWebIdentity: d.OutboundWebIdentity, identity: d.Identity, organizations: d.Organizations, tokenPreferences: d.TokenPreferences, regions: d.Regions, now: d.Clock.Now, apiEvents: d.APIEvents}
}
