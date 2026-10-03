// Package identity owns local AWS credentials shared by authentication, IAM,
// and STS. Callers receive copies; secrets remain confined to the credential
// resolver and the initial credential-issuance response.
package identity

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"stackd/journal"
)

var (
	ErrNotFound           = errors.New("credential does not exist")
	ErrInactive           = errors.New("credential is inactive")
	ErrExpired            = errors.New("credential has expired")
	ErrLimitExceeded      = errors.New("access key quota exceeded")
	ErrInvalidPrincipal   = errors.New("invalid credential principal")
	ErrInvalidDuration    = errors.New("invalid session duration")
	ErrSessionCredentials = errors.New("session credentials cannot issue GetSessionToken credentials")
)

// Principal identifies an account root or IAM identity independently of its keys.
// ID is stable through an IAM user rename; ARN and UserName are updated together.
type Principal struct {
	AccountID string
	ARN       string
	ID        string
	UserName  string
}

// Credential contains material needed to verify one signed request. Expiration
// is zero for long-term access keys. A session always requires SessionToken.
type Credential struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	// DefaultRegionsOnly records legacy global STS token compatibility at issue
	// time. Later IAM preference changes cannot alter an issued credential.
	DefaultRegionsOnly bool
	AccountID          string
	PrincipalARN       string
	PrincipalID        string
	UserName           string
	Expiration         time.Time
	CreateDate         time.Time
	SessionType        SessionType
	IssuerARN          string
	IssuerID           string
	SessionPolicies    []string
	SessionPolicyARNs  []string
	HasSessionPolicy   bool
	// SessionContext contains authenticated federation claims or service-issued
	// source context, including Lambda's unqualified source function ARN.
	SessionContext     map[string][]string
	FederatedProvider  string
	SessionTags        map[string]string
	TransitiveTagKeys  []string
	SourceIdentity     string
	MFAPresent         bool
	MFAAuthenticatedAt time.Time
	// RequestParentEventID attributes requests made with a service-issued
	// credential. It is journal metadata, never an IAM condition or authority.
	RequestParentEventID string
	// InScopeOf is public source-resource identity supplied by the issuing
	// authority, not an IAM condition or a scope inferred by the HTTP caller.
	InScopeOf journal.APIIdentityScope
}

// SessionType records how temporary credentials were issued, since AWS applies
// different service restrictions to user sessions and service-issued identities.
type SessionType string

const (
	SessionTypeGetSessionToken SessionType = "GetSessionToken"
	SessionTypeAssumeRole      SessionType = "AssumeRole"
	SessionTypeAssumeRoot      SessionType = "AssumeRoot"
	SessionTypeFederation      SessionType = "GetFederationToken"
	// EC2 intrinsic credentials identify the instance, not an attached IAM role.
	// Their service-use boundary is independent of identity/resource policies.
	SessionTypeEC2InstanceIdentity SessionType = "EC2InstanceIdentity"
)

func cloneCredential(c Credential) Credential {
	c.SessionPolicies = slices.Clone(c.SessionPolicies)
	c.SessionPolicyARNs = slices.Clone(c.SessionPolicyARNs)
	c.SessionContext = cloneSessionContext(c.SessionContext)
	c.SessionTags = maps.Clone(c.SessionTags)
	c.TransitiveTagKeys = slices.Clone(c.TransitiveTagKeys)
	return c
}

func (c Credential) String() string {
	return fmt.Sprintf("Credential{AccessKeyID:%q AccountID:%q PrincipalID:%q Expiration:%s}", c.AccessKeyID, c.AccountID, c.PrincipalID, c.Expiration.Format(time.RFC3339))
}

func (c Credential) GoString() string { return c.String() }

// Status controls whether a long-term key can authenticate requests.
type Status string

const (
	Active   Status = "Active"
	Inactive Status = "Inactive"
)

// AccessKey is metadata safe to return from listing APIs: it contains no secret.
type AccessKey struct {
	AccessKeyID string
	Principal   Principal
	Status      Status
	CreateDate  time.Time
}

// LastUsed describes authenticated usage recorded by the gateway. Long-term
// keys retain the first use in each fifteen-minute span; temporary credentials
// retain their latest use so role activity is independent of key reporting.
// An unused key has a zero Date and N/A for Service and Region.
type LastUsed struct {
	Date    time.Time
	Service string
	Region  string
}

// Recorded distinguishes unused credentials from usage at the modeled zero
// instant. Service identifies an authenticated use even when Date is zero.
func (u LastUsed) Recorded() bool {
	return !u.Date.IsZero() || (u.Service != "" && u.Service != "N/A")
}

func cloneSessionContext(values map[string][]string) map[string][]string {
	if values == nil {
		return nil
	}
	result := make(map[string][]string, len(values))
	for key, value := range values {
		result[key] = slices.Clone(value)
	}
	return result
}
