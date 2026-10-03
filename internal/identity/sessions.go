package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"maps"
	"slices"
	"strings"
	"time"

	"stackd/journal"
)

// SessionSpec contains the verified GetSessionToken authentication and endpoint
// compatibility. MFAAuthenticatedAt can be the zero epoch when MFAPresent is true.
type SessionSpec struct {
	Duration           time.Duration
	MFAPresent         bool
	MFAAuthenticatedAt time.Time
	DefaultRegionsOnly bool
}

// IssueSession creates GetSessionToken credentials derived from a live long-term
// key. Existing sessions are independent of changes to the source access key.
func (s *Store) IssueSession(ctx context.Context, parent Credential, spec SessionSpec) (Credential, error) {
	duration := spec.Duration
	if duration < 15*time.Minute || duration > 36*time.Hour {
		return Credential{}, ErrInvalidDuration
	}
	return s.issue(ctx, parent, func(current Credential, instant time.Time) (Credential, error) {
		if current.SessionToken != "" {
			return Credential{}, ErrSessionCredentials
		}
		if current.PrincipalID == current.AccountID && duration > time.Hour {
			duration = time.Hour
		}
		c, err := newCredential(Principal{AccountID: current.AccountID, ARN: current.PrincipalARN, ID: current.PrincipalID, UserName: current.UserName}, "ASIA", instant)
		if err != nil {
			return Credential{}, err
		}
		c.SessionType = SessionTypeGetSessionToken
		c.MFAPresent = spec.MFAPresent
		c.MFAAuthenticatedAt = spec.MFAAuthenticatedAt
		c.DefaultRegionsOnly = spec.DefaultRegionsOnly
		c.Expiration = c.CreateDate.Add(duration)
		return c, nil
	})
}

// RoleSessionSpec contains an already-authorized role assumption. Role identifies
// the immutable IAM role; session constraints are snapshots of the STS request.
// The role's current identity policies are deliberately not copied into a token.
type RoleSessionSpec struct {
	DefaultRegionsOnly bool
	Role               Principal
	SessionName        string
	Duration           time.Duration
	// MaxSessionDuration constrains user and federated assumptions, not AWS services.
	MaxSessionDuration   time.Duration
	Policies             []string
	PolicyARNs           []string
	HasSessionPolicy     bool
	Tags                 map[string]string
	TransitiveTagKeys    []string
	SourceIdentity       string
	SessionContext       map[string][]string
	FederatedProvider    string
	NotAfter             time.Time
	RequestParentEventID string
	// InScopeOf is public audit origin supplied by the issuing service.
	InScopeOf journal.APIIdentityScope
}

func (s *Store) IssueRoleSession(ctx context.Context, parent Credential, spec RoleSessionSpec) (Credential, error) {
	if !validPrincipal(spec.Role) || !strings.Contains(spec.Role.ARN, ":role/") || spec.SessionName == "" {
		return Credential{}, ErrInvalidPrincipal
	}
	if spec.Duration < 15*time.Minute || spec.Duration > 12*time.Hour || spec.Duration > spec.MaxSessionDuration {
		return Credential{}, ErrInvalidDuration
	}
	return s.issue(ctx, parent, func(current Credential, instant time.Time) (Credential, error) {
		if current.SessionType == SessionTypeFederation || current.SessionType == SessionTypeEC2InstanceIdentity {
			return Credential{}, ErrSessionCredentials
		}
		if current.SessionType == SessionTypeAssumeRole && spec.Duration > time.Hour {
			return Credential{}, ErrInvalidDuration
		}
		return newRoleCredential(spec, instant)
	})
}

// FederationSpec is an authorized federation request. An empty session policy
// still limits federation sessions to no identity-derived permissions.
type FederationSpec struct {
	DefaultRegionsOnly bool
	Name               string
	Duration           time.Duration
	Policies           []string
	PolicyARNs         []string
	Tags               map[string]string
}

func (s *Store) IssueFederation(ctx context.Context, parent Credential, spec FederationSpec) (Credential, error) {
	if spec.Duration < 15*time.Minute || spec.Duration > 36*time.Hour {
		return Credential{}, ErrInvalidDuration
	}
	if spec.Name == "" {
		return Credential{}, ErrInvalidPrincipal
	}
	return s.issue(ctx, parent, func(current Credential, instant time.Time) (Credential, error) {
		if current.SessionToken != "" {
			return Credential{}, ErrSessionCredentials
		}
		if current.PrincipalID == current.AccountID && spec.Duration > time.Hour {
			spec.Duration = time.Hour
		}
		parts := strings.SplitN(current.PrincipalARN, ":", 6)
		p := Principal{AccountID: current.AccountID, ARN: "arn:" + parts[1] + ":sts::" + current.AccountID + ":federated-user/" + spec.Name, ID: current.AccountID + ":" + spec.Name}
		c, err := newCredential(p, "ASIA", instant)
		if err != nil {
			return Credential{}, err
		}
		c.SessionType = SessionTypeFederation
		c.DefaultRegionsOnly = spec.DefaultRegionsOnly
		c.IssuerARN = current.PrincipalARN
		c.IssuerID = current.PrincipalID
		c.SessionPolicies = slices.Clone(spec.Policies)
		c.SessionPolicyARNs = slices.Clone(spec.PolicyARNs)
		c.HasSessionPolicy = true
		c.SessionTags = maps.Clone(spec.Tags)
		c.Expiration = c.CreateDate.Add(spec.Duration)
		return c, nil
	})
}

func (s *Store) issue(ctx context.Context, parent Credential, build func(Credential, time.Time) (Credential, error)) (Credential, error) {
	var credential Credential
	err := s.repository.Update(ctx, func(tx Transaction) error {
		instant := s.now()
		current, err := s.resolve(tx, parent.AccessKeyID, instant)
		if err != nil {
			return err
		}
		if current.AccountID != parent.AccountID || current.PrincipalID != parent.PrincipalID {
			return ErrInvalidPrincipal
		}
		if current.SessionType == "" && (current.AccessKeyID == "test" || current.AccessKeyID == current.AccountID) {
			p := Principal{AccountID: parent.AccountID, ARN: parent.PrincipalARN, ID: parent.PrincipalID}
			if !validPrincipal(p) {
				return ErrInvalidPrincipal
			}
			current.PrincipalARN = parent.PrincipalARN
		}
		credential, err = build(current, instant)
		if err != nil {
			return err
		}
		return putSession(tx, &credential)
	})
	if err != nil {
		return Credential{}, err
	}
	return credential, nil
}

// AccessKeyAccount returns the owning account even for inactive or expired keys;
// it reveals neither key status nor credentials.
func (s *Store) AccessKeyAccount(ctx context.Context, key string) (string, error) {
	var account string
	err := s.repository.View(ctx, func(reader Reader) error {
		if root, ok := s.rootCredential(key); ok {
			account = root.AccountID
			return nil
		}
		r, err := reader.Get(key)
		if err != nil {
			return err
		}
		account = r.Credential.AccountID
		return nil
	})
	return account, err
}

// IssueFederatedRoleSession issues credentials after a trusted federation
// authority has authenticated an external identity and authorized the role.
// It does not resolve or synthesize an AWS parent credential. The authority must
// bind this store to its IAM write transaction before calling it.
func (s *Store) IssueFederatedRoleSession(ctx context.Context, spec RoleSessionSpec) (Credential, error) {
	if spec.Duration > spec.MaxSessionDuration {
		return Credential{}, ErrInvalidDuration
	}
	return s.issueAuthorizedRoleSession(ctx, spec)
}

// IssueServiceRoleSession issues an AWS service's trust-authorized role session.
// Role MaxSessionDuration does not constrain AWS services. The caller must bind
// this store to the IAM transaction that evaluated the current role trust.
func (s *Store) IssueServiceRoleSession(ctx context.Context, spec RoleSessionSpec) (Credential, error) {
	return s.issueAuthorizedRoleSession(ctx, spec)
}

func (s *Store) issueAuthorizedRoleSession(ctx context.Context, spec RoleSessionSpec) (Credential, error) {
	if !validPrincipal(spec.Role) || !strings.Contains(spec.Role.ARN, ":role/") || spec.SessionName == "" {
		return Credential{}, ErrInvalidPrincipal
	}
	if spec.Duration < 15*time.Minute || spec.Duration > 12*time.Hour {
		return Credential{}, ErrInvalidDuration
	}
	var credential Credential
	err := s.repository.Update(ctx, func(tx Transaction) error {
		instant := s.now()
		var err error
		credential, err = newRoleCredential(spec, instant)
		if err != nil {
			return err
		}
		return putSession(tx, &credential)
	})
	if err != nil {
		return Credential{}, err
	}
	return credential, nil
}

func newRoleCredential(spec RoleSessionSpec, instant time.Time) (Credential, error) {
	parts := strings.SplitN(spec.Role.ARN, ":", 6)
	name := parts[5][strings.LastIndex(parts[5], "/")+1:]
	p := Principal{AccountID: spec.Role.AccountID, ARN: "arn:" + parts[1] + ":sts::" + spec.Role.AccountID + ":assumed-role/" + name + "/" + spec.SessionName, ID: spec.Role.ID + ":" + spec.SessionName}
	c, err := newCredential(p, "ASIA", instant)
	if err != nil {
		return Credential{}, err
	}
	c.SessionType = SessionTypeAssumeRole
	c.DefaultRegionsOnly = spec.DefaultRegionsOnly
	c.IssuerARN, c.IssuerID = spec.Role.ARN, spec.Role.ID
	c.SessionPolicies = slices.Clone(spec.Policies)
	c.SessionPolicyARNs = slices.Clone(spec.PolicyARNs)
	c.HasSessionPolicy = spec.HasSessionPolicy
	c.SessionTags = maps.Clone(spec.Tags)
	c.TransitiveTagKeys = slices.Clone(spec.TransitiveTagKeys)
	c.SourceIdentity = spec.SourceIdentity
	c.SessionContext = cloneSessionContext(spec.SessionContext)
	c.FederatedProvider = spec.FederatedProvider
	c.RequestParentEventID = spec.RequestParentEventID
	c.InScopeOf = spec.InScopeOf
	// MFA on the assumption request does not become session MFA context.
	c.Expiration = c.CreateDate.Add(spec.Duration)
	if !spec.NotAfter.IsZero() && spec.NotAfter.Before(c.Expiration) {
		c.Expiration = spec.NotAfter
	}
	if !c.Expiration.After(c.CreateDate) {
		return Credential{}, ErrExpired
	}
	return c, nil
}

// Session tokens are opaque random handles. AWS does not publish their encoding
// or fixed size; v2 handles retain its documented larger-storage requirement.
func putSession(tx Transaction, credential *Credential) error {
	size := 96
	if credential.DefaultRegionsOnly {
		size = 48
	}
	token := make([]byte, size)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	credential.SessionToken = base64.StdEncoding.EncodeToString(token)
	return putNew(tx, *credential)
}
