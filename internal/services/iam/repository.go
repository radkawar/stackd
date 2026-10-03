package iam

import (
	"context"
	"errors"
	"stackd/internal/identity"
)

// Scope identifies IAM's global resource namespace. Regions share one account
// namespace; different AWS partitions never share IAM resources.
type Scope struct {
	Partition string
	AccountID string
}

var (
	ErrRecordNotFound    = errors.New("IAM record does not exist")
	ErrClosedTransaction = errors.New("IAM transaction is closed")
)

// ReadTx reads detached typed resource records from a consistent snapshot.
// Records and their nested maps belong to the caller; mutating a returned value
// never writes state. A transaction is valid only during its repository callback.
type ReadTx interface {
	// Context carries this transaction into related typed repositories. Its
	// values and deadline derive from the request; callers must not retain it
	// beyond the callback or use it concurrently.
	Context() context.Context
	AccountMetadata(Scope) (AccountMetadata, error)
	CredentialReport(Scope) (CredentialReportRecord, error)
	CredentialReportScopes() ([]Scope, error)
	PrincipalActivities(Scope) ([]PrincipalActivity, error)
	AccessReport(Scope, string) (AccessReport, error)
	LatestOrganizationAccessReport(scope Scope, owner, entityPath, policyID string) (AccessReport, error)
	PendingAccessReports(Scope) ([]AccessReport, error)
	AccessReportScopes() ([]Scope, error)
	SigningCertificate(Scope, string) (SigningCertificateRecord, error)
	SigningCertificates(Scope) ([]SigningCertificateRecord, error)
	SSHPublicKey(Scope, string) (SSHPublicKeyRecord, error)
	SSHPublicKeys(Scope) ([]SSHPublicKeyRecord, error)
	ServerCertificate(Scope, string) (ServerCertificateRecord, error)
	ServerCertificates(Scope) ([]ServerCertificateRecord, error)

	Scopes(partition string) ([]Scope, error)
	User(Scope, string) (User, error)
	Users(Scope) ([]User, error)
	Group(Scope, string) (Group, error)
	Groups(Scope) ([]Group, error)
	Role(Scope, string) (Role, error)
	Roles(Scope) ([]Role, error)
	ManagedPolicy(Scope, string) (ManagedPolicy, error)
	ManagedPolicies(Scope) ([]ManagedPolicy, error)
	MFADevice(Scope, string) (MFADevice, error)
	MFADevices(Scope) ([]MFADevice, error)
	InstanceProfile(Scope, string) (InstanceProfile, error)
	InstanceProfiles(Scope) ([]InstanceProfile, error)
	LoginProfile(Scope, string) (LoginProfileRecord, error)
	LoginProfiles(Scope) ([]LoginProfileRecord, error)
	ServiceCredential(Scope, string) (ServiceCredentialRecord, error)
	ServiceCredentials(Scope) ([]ServiceCredentialRecord, error)
	OIDCProvider(Scope, string) (OIDCProviderRecord, error)
	OIDCProviders(Scope) ([]OIDCProviderRecord, error)
	SAMLProvider(Scope, string) (SAMLProviderRecord, error)
	SAMLProviders(Scope) ([]SAMLProviderRecord, error)
	ServiceLinkedRoleDeletion(Scope, string) (ServiceLinkedRoleDeletion, error)
	ServiceLinkedRoleDeletions(Scope) ([]ServiceLinkedRoleDeletion, error)
	ServiceLinkedRoleDeletionScopes() ([]Scope, error)
	AccountSettings(Scope) (AccountSettingsRecord, error)
	AccountAliasOwner(partition, alias string) (string, error)
	Credential(string) (identity.Record, error)
	PrincipalCredentials(accountID, principalID string) ([]identity.Record, error)
}

// WriteTx changes individual typed IAM resources atomically. IAM operation code
// uses an operation-local working set; no generic resource blobs or live maps
// cross the repository boundary.
type WriteTx interface {
	PutAccountMetadata(Scope, AccountMetadata) error
	PutCredentialReport(Scope, CredentialReportRecord) error
	PutPrincipalActivity(Scope, PrincipalActivity) error
	PutAccessReport(Scope, AccessReport) error
	PutSigningCertificate(Scope, SigningCertificateRecord) error
	DeleteSigningCertificate(Scope, string) error
	PutSSHPublicKey(Scope, SSHPublicKeyRecord) error
	DeleteSSHPublicKey(Scope, string) error
	PutServerCertificate(Scope, ServerCertificateRecord) error
	DeleteServerCertificate(Scope, string) error

	ReadTx
	PutUser(Scope, User) error
	DeleteUser(Scope, string) error
	PutGroup(Scope, Group) error
	DeleteGroup(Scope, string) error
	PutRole(Scope, Role) error
	DeleteRole(Scope, string) error
	PutManagedPolicy(Scope, ManagedPolicy) error
	DeleteManagedPolicy(Scope, string) error
	PutMFADevice(Scope, MFADevice) error
	DeleteMFADevice(Scope, string) error
	PutInstanceProfile(Scope, InstanceProfile) error
	DeleteInstanceProfile(Scope, string) error
	PutLoginProfile(Scope, LoginProfileRecord) error
	DeleteLoginProfile(Scope, string) error
	PutServiceCredential(Scope, ServiceCredentialRecord) error
	DeleteServiceCredential(Scope, string) error
	PutOIDCProvider(Scope, OIDCProviderRecord) error
	DeleteOIDCProvider(Scope, string) error
	PutSAMLProvider(Scope, SAMLProviderRecord) error
	DeleteSAMLProvider(Scope, string) error
	PutServiceLinkedRoleDeletion(Scope, ServiceLinkedRoleDeletion) error
	PutAccountSettings(Scope, AccountSettingsRecord) error
	PutCredential(identity.Record) error
	DeleteCredential(string) error
}

// Repository supplies atomic IAM transactions. Update must roll back every
// write if its callback fails or the request is canceled before commit.
// Implementations may use memory or service-owned relational tables.
type Repository interface {
	View(context.Context, func(ReadTx) error) error
	Update(context.Context, func(WriteTx) error) error
	// Attempt isolates an authority command's writes from an enclosing write,
	// so a rejected command can record its outcome after its savepoint rolls back.
	Attempt(context.Context, func(WriteTx) error) error
}
