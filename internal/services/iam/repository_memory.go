package iam

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"stackd/internal/identity"
	"stackd/storage/memory"
)

// MemoryRepository is a process-local IAM backend with snapshot reads and
// copy-on-write transactions. It has no process-global state.
type MemoryRepository struct {
	store *memory.Store[memoryState]
}

type memoryState struct {
	accountMetadata     map[Scope]AccountMetadata
	credentialReports   map[Scope]CredentialReportRecord
	principalActivities map[Scope]map[principalActivityKey]PrincipalActivity
	accessReports       map[Scope]map[string]AccessReport
	signingCertificates map[Scope]map[string]SigningCertificateRecord
	sshKeys             map[Scope]map[string]SSHPublicKeyRecord
	serverCertificates  map[Scope]map[string]ServerCertificateRecord

	users                  map[Scope]map[string]User
	groups                 map[Scope]map[string]Group
	roles                  map[Scope]map[string]Role
	policies               map[Scope]map[string]ManagedPolicy
	mfaDevices             map[Scope]map[string]MFADevice
	instanceProfiles       map[Scope]map[string]InstanceProfile
	loginProfiles          map[Scope]map[string]LoginProfileRecord
	serviceCredentials     map[Scope]map[string]ServiceCredentialRecord
	oidcProviders          map[Scope]map[string]OIDCProviderRecord
	samlProviders          map[Scope]map[string]SAMLProviderRecord
	serviceLinkedDeletions map[Scope]map[string]ServiceLinkedRoleDeletion
	accountSettings        map[Scope]AccountSettingsRecord
	credentials            map[string]identity.Record
}

// NewMemoryRepository returns an empty transactional IAM repository. A nil
// domain creates isolated storage; shared domains coordinate typed repositories.
func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{
		accountMetadata: make(map[Scope]AccountMetadata), credentialReports: make(map[Scope]CredentialReportRecord),
		principalActivities: make(map[Scope]map[principalActivityKey]PrincipalActivity),
		accessReports:       make(map[Scope]map[string]AccessReport),
		signingCertificates: make(map[Scope]map[string]SigningCertificateRecord),
		sshKeys:             make(map[Scope]map[string]SSHPublicKeyRecord),
		serverCertificates:  make(map[Scope]map[string]ServerCertificateRecord),

		users: make(map[Scope]map[string]User), groups: make(map[Scope]map[string]Group), roles: make(map[Scope]map[string]Role),
		policies: make(map[Scope]map[string]ManagedPolicy), credentials: make(map[string]identity.Record), mfaDevices: make(map[Scope]map[string]MFADevice),
		instanceProfiles: make(map[Scope]map[string]InstanceProfile), loginProfiles: make(map[Scope]map[string]LoginProfileRecord), accountSettings: make(map[Scope]AccountSettingsRecord),
		serviceCredentials: make(map[Scope]map[string]ServiceCredentialRecord), oidcProviders: make(map[Scope]map[string]OIDCProviderRecord), samlProviders: make(map[Scope]map[string]SAMLProviderRecord),
		serviceLinkedDeletions: make(map[Scope]map[string]ServiceLinkedRoleDeletion),
	}
	return &MemoryRepository{store: memory.New(domain, initial, cloneMemoryState)}
}

type memoryTx struct {
	state *memoryState
	tx    *memory.Transaction
}

func (t *memoryTx) Context() context.Context { return t.tx.Context() }

func (r *MemoryRepository) View(ctx context.Context, fn func(ReadTx) error) error {
	return r.store.View(ctx, func(state *memoryState, tx *memory.Transaction) error {
		return fn(&memoryTx{state: state, tx: tx})
	})
}

func (r *MemoryRepository) Update(ctx context.Context, fn func(WriteTx) error) error {
	return r.store.Update(ctx, func(state *memoryState, tx *memory.Transaction) error {
		return fn(&memoryTx{state: state, tx: tx})
	})
}

func (r *MemoryRepository) Attempt(ctx context.Context, fn func(WriteTx) error) error {
	return r.store.Attempt(ctx, func(state *memoryState, tx *memory.Transaction) error {
		return fn(&memoryTx{state: state, tx: tx})
	})
}

func cloneMemoryState(state memoryState) memoryState {
	return memoryState{
		accountMetadata: maps.Clone(state.accountMetadata), credentialReports: maps.Clone(state.credentialReports),
		principalActivities: memory.CloneTables(state.principalActivities),
		accessReports:       memory.CloneTables(state.accessReports),
		signingCertificates: memory.CloneTables(state.signingCertificates),
		sshKeys:             memory.CloneTables(state.sshKeys),
		serverCertificates:  memory.CloneTables(state.serverCertificates),

		users: memory.CloneTables(state.users), groups: memory.CloneTables(state.groups), roles: memory.CloneTables(state.roles),
		policies: memory.CloneTables(state.policies), credentials: maps.Clone(state.credentials), mfaDevices: memory.CloneTables(state.mfaDevices),
		instanceProfiles: memory.CloneTables(state.instanceProfiles), loginProfiles: memory.CloneTables(state.loginProfiles), accountSettings: maps.Clone(state.accountSettings),
		serviceCredentials: memory.CloneTables(state.serviceCredentials), oidcProviders: memory.CloneTables(state.oidcProviders), samlProviders: memory.CloneTables(state.samlProviders),
		serviceLinkedDeletions: memory.CloneTables(state.serviceLinkedDeletions),
	}
}

func (t *memoryTx) check(write bool) error {
	err := t.tx.Check(write)
	if errors.Is(err, memory.ErrClosedTransaction) {
		return ErrClosedTransaction
	}
	return err
}

func (t *memoryTx) Scopes(partition string) ([]Scope, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	seen := make(map[Scope]bool)
	for scope := range t.state.accessReports {
		if scope.Partition == partition {
			seen[scope] = true
		}
	}
	for scope := range t.state.principalActivities {
		if scope.Partition == partition {
			seen[scope] = true
		}
	}
	for scope := range t.state.accountMetadata {
		if scope.Partition == partition {
			seen[scope] = true
		}
	}
	for scope := range t.state.credentialReports {
		if scope.Partition == partition {
			seen[scope] = true
		}
	}
	for s := range t.state.signingCertificates {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.sshKeys {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.serverCertificates {
		if s.Partition == partition {
			seen[s] = true
		}
	}

	for s := range t.state.users {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.groups {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.roles {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.policies {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.mfaDevices {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.instanceProfiles {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.loginProfiles {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.accountSettings {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.serviceCredentials {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.oidcProviders {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.samlProviders {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	for s := range t.state.serviceLinkedDeletions {
		if s.Partition == partition {
			seen[s] = true
		}
	}
	result := make([]Scope, 0, len(seen))
	for sc := range seen {
		result = append(result, sc)
	}
	slices.SortFunc(result, func(a, b Scope) int { return strings.Compare(a.AccountID, b.AccountID) })
	return result, nil
}

func cloneUser(u User) User {
	if u.PasswordLastUsed != nil {
		t := *u.PasswordLastUsed
		u.PasswordLastUsed = &t
	}
	u.Tags = slices.Clone(u.Tags)
	u.IdentityPolicies = cloneIdentityPolicies(u.IdentityPolicies)
	if u.PermissionsBoundary != nil {
		b := *u.PermissionsBoundary
		u.PermissionsBoundary = &b
	}
	return u
}
func cloneGroup(g Group) Group {
	g.IdentityPolicies = cloneIdentityPolicies(g.IdentityPolicies)
	g.Members = maps.Clone(g.Members)
	g.MemberOwners = maps.Clone(g.MemberOwners)
	g.MembershipClaims = maps.Clone(g.MembershipClaims)
	return g
}
func cloneRole(r Role) Role {
	r.Tags = slices.Clone(r.Tags)
	r.IdentityPolicies = cloneIdentityPolicies(r.IdentityPolicies)
	r.TrustPrincipalIDs = maps.Clone(r.TrustPrincipalIDs)
	if r.SourceRoleTemplate != nil {
		source := *r.SourceRoleTemplate
		source.Parameters = make(map[string][]string, len(r.SourceRoleTemplate.Parameters))
		for name, values := range r.SourceRoleTemplate.Parameters {
			source.Parameters[name] = slices.Clone(values)
		}
		r.SourceRoleTemplate = &source
	}
	if r.PermissionsBoundary != nil {
		b := *r.PermissionsBoundary
		r.PermissionsBoundary = &b
	}
	return r
}
func clonePolicy(p ManagedPolicy) ManagedPolicy {
	p.Tags = slices.Clone(p.Tags)
	versions := make(map[string]*PolicyVersion, len(p.Versions))
	for id, version := range p.Versions {
		if version != nil {
			v := *version
			versions[id] = &v
		}
	}
	p.Versions = versions
	return p
}
func cloneIdentityPolicies(p IdentityPolicies) IdentityPolicies {
	return IdentityPolicies{Inline: maps.Clone(p.Inline), Attached: maps.Clone(p.Attached), InlineOwners: maps.Clone(p.InlineOwners), AttachedOwners: maps.Clone(p.AttachedOwners), CloudFormationOwner: p.CloudFormationOwner}
}
