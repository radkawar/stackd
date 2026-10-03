package sts

import (
	"context"
	"time"

	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/identity"
)

// FederationProviderReference identifies the exact IAM trust configuration used
// to authenticate a token. The authority revalidates it before issuing a session.
type FederationProviderReference struct{ ARN, ID, Version string }

// FederatedCredentialIssuer is valid only inside its authority callback. The
// callback must authorize the current role before calling this trusted boundary.
type FederatedCredentialIssuer interface {
	IssueFederatedRoleSession(context.Context, identity.RoleSessionSpec) (identity.Credential, error)
}

// FederationAuthority keeps provider validation, current role trust evaluation
// and credential insertion in one transaction. The callback runs once and may
// use RoleSource with the supplied context to read that same snapshot.
type FederationAuthority interface {
	WithFederationSession(context.Context, FederationProviderReference, string, func(context.Context, RoleSnapshot, FederatedCredentialIssuer) error) error
}

// FederatedRoleRequest contains claims verified by the OIDC/SAML adapters, not
// caller-provided AWS identity metadata. TrustContext applies only to assumption;
// SessionContext includes only documented claims available in issued sessions.
type FederatedRoleRequest struct {
	Action, ProviderARN, ProviderID, ProviderVersion string
	RoleARN, SessionName, SourceIdentity, Subject    string
	Duration                                         time.Duration
	NotAfter                                         time.Time
	// AuthenticationNotAfter is the exclusive token validity deadline after
	// applying the provider's allowed skew. It does not cap issued credentials.
	AuthenticationNotAfter       *time.Time
	Policy                       string
	PolicyARNs                   stsapi.PolicyDescriptorListType
	HasSessionPolicy             bool
	RoleAuthorizedByIDP          bool
	Tags                         map[string]string
	TransitiveTagKeys            []string
	TrustContext, SessionContext map[string][]string
}

type FederatedRoleResult struct {
	Credential       identity.Credential
	PackedPolicySize int32
}
