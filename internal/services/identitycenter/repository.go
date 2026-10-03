// Package identitycenter owns IAM Identity Center administration and browser sessions.
package identitycenter

import (
	"context"
	"errors"
	"stackd/internal/identity"
	"stackd/internal/services/identitystore"
	"time"
)

var ErrNotFound = errors.New("identity center resource not found")

type Scope struct{ Partition, AccountID, Region string }
type Instance struct {
	Scope
	ARN, StoreID, Name, ClientToken string
	Created                         time.Time
	Tags                            map[string]string
}
type PolicyReference struct{ Name, Path string }
type PermissionSet struct {
	InstanceARN, ARN, Name, Description, RelayState, InlinePolicy string
	Duration                                                      time.Duration
	Created                                                       time.Time
	ManagedPolicies                                               []string
	CustomerManagedPolicies                                       []PolicyReference
	BoundaryARN                                                   string
	Boundary                                                      PolicyReference
	Tags                                                          map[string]string
}
type Assignment struct{ InstanceARN, PermissionSetARN, AccountID, PrincipalType, PrincipalID string }
type Provisioning struct{ InstanceARN, PermissionSetARN, AccountID, RoleARN, RoleID, RoleName string }
type Operation struct {
	InstanceARN, ID, Kind, PermissionSetARN, AccountID, PrincipalType, PrincipalID string
	Created                                                                        time.Time
}
type Client struct {
	ID, SecretHash, Name, Region, Partition string
	Created, Expires                        time.Time
	Scopes, GrantTypes                      []string
	RedirectURIs                            []string
	IssuerURL                               string
}
type Device struct {
	CodeHash, UserCode, ClientID, InstanceARN, UserID, CSRF, State string
	Created, Expires, LastPoll                                     time.Time
	Interval                                                       int32
}
type Authorization struct {
	ID, CodeHash, ClientID, InstanceARN, UserID, RedirectURI, Challenge, Scope, OAuthState, CSRF, State string
	Created, Expires                                                                                    time.Time
}
type Session struct {
	ID, FamilyID, ClientID, InstanceARN, UserID, AccessHash, RefreshHash string
	Created, AccessExpires, RefreshExpires                               time.Time
	Revoked                                                              bool
}

type Reader interface {
	Context() context.Context
	Instance(string) (Instance, error)
	Instances(Scope) ([]Instance, error)
	PermissionSet(string) (PermissionSet, error)
	PermissionSets(string) ([]PermissionSet, error)
	Assignments(string) ([]Assignment, error)
	Provisionings(string) ([]Provisioning, error)
	Operation(string) (Operation, error)
	Operations(string) ([]Operation, error)
	Client(string) (Client, error)
	Device(string) (Device, error)
	DeviceByUserCode(string) (Device, error)
	Authorization(string) (Authorization, error)
	AuthorizationByCode(string) (Authorization, error)
	SessionByAccess(string) (Session, error)
	SessionByRefresh(string) (Session, error)
	Sessions(string) ([]Session, error)
}
type Transaction interface {
	Reader
	PutInstance(Instance) error
	DeleteInstance(string) error
	PutPermissionSet(PermissionSet) error
	DeletePermissionSet(string) error
	PutAssignment(Assignment) error
	DeleteAssignment(Assignment) error
	PutProvisioning(Provisioning) error
	DeleteProvisioning(Provisioning) error
	PutOperation(Operation) error
	PutClient(Client) error
	PutDevice(Device) error
	PutAuthorization(Authorization) error
	PutSession(Session) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

// Directory reads current membership in the enclosing identity transaction.
type Directory interface {
	EnsureStore(context.Context, identitystore.Scope, string) error
	DeleteStore(context.Context, identitystore.Scope, string) error
	FindUser(context.Context, identitystore.Scope, string, string) (identitystore.User, error)
	UserByName(context.Context, identitystore.Scope, string, string) (identitystore.User, error)
	GroupExists(context.Context, identitystore.Scope, string, string) (bool, error)
	IsMember(context.Context, identitystore.Scope, string, string, string) (bool, error)
}

// Login authenticates through the explicitly configured existing identity provider.
// It returns the canonical username, never caller-selected AWS principal metadata.
type Login interface {
	Authenticate(context.Context, string, string) (string, error)
}
type RoleSpec struct {
	Instance      Instance
	PermissionSet PermissionSet
	AccountID     string
}

// Roles delegates all resource and credential authority to IAM/STS owners.
type Roles interface {
	Provision(context.Context, RoleSpec) (Provisioning, error)
	Remove(context.Context, Provisioning) error
	Credentials(context.Context, Instance, PermissionSet, Provisioning, string) (identity.Credential, error)
}

// Accounts validates that a target is the instance owner or a current member of
// the owner's organization. It does not treat an arbitrary account ID as owned.
type Accounts interface {
	Allowed(context.Context, Scope, string) (bool, error)
}
