// Package ram owns resource shares and resolves all grants against current resource owners.
package ram

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("RAM resource not found")
var ErrUnsupportedResource = errors.New("resource type is not supported for sharing")

type Scope struct{ Partition, AccountID, Region string }

// ResourceIdentity is resolved by the authoritative owner, never inferred from an ARN.
// Owners call ResourceDeleted in their deletion transaction before a name can be reused.
type ResourceIdentity struct {
	ARN, ResourceType, Partition, AccountID, Region string
	OrganizationOnly, SupportsIAMPrincipals         bool
}
type ResourceOwner interface {
	ResolveResource(context.Context, string) (ResourceIdentity, error)
}
type PolicyResourceOwner interface {
	RemoveResourcePolicy(context.Context, string, string, string) error
}

// Eligible checks current organization membership and RAM trusted access. An empty
// recipient validates an organization/OU principal without selecting a member.
type Organization interface {
	Eligible(context.Context, string, string, string) (bool, error)
	EnableSharing(context.Context, string) (bool, error)
}
type PermissionQuery struct{ ResourceARN, AccountID, Action string }
type SharedResourcesQuery struct{ Partition, Region, AccountID, ResourceType, Action string }

type Share struct {
	Scope
	ARN, Name, Status, FeatureSet, PolicyID string
	AllowExternal, RetainOnLeave            bool
	Created, Updated                        time.Time
	Tags                                    map[string]string
	Resources                               []ResourceAssociation
	Principals                              []PrincipalAssociation
	Permissions                             []PermissionAssociation
}
type ResourceAssociation struct {
	ResourceIdentity
	Status           string
	Created, Updated time.Time
	StatusMessage    string
}
type PrincipalAssociation struct {
	Principal, PrincipalID, Status, InvitationARN string
	Organization                                  bool
	Created, Updated                              time.Time
}
type PermissionAssociation struct {
	ARN, ResourceType string
	Version           int32
}
type Invitation struct {
	Scope
	ARN, ShareARN, ShareName, Sender, Receiver, Status string
	Created, Updated                                   time.Time
}
type Permission struct {
	Scope
	ARN, Name, ResourceType, Type, FeatureSet, Status string
	ResourceTypeDefault                               bool
	DefaultVersion                                    int32
	Created, Updated                                  time.Time
	Tags                                              map[string]string
	Versions                                          []PermissionVersion
}
type PermissionVersion struct {
	Version          int32
	Document         string
	Actions          []string
	Created, Updated time.Time
	Deleted          bool
}

// Receipt binds an idempotency token to its operation, normalized request hash,
// and typed result identity. It never stores an opaque request or response blob.
type Replacement struct {
	Scope
	ID, FromARN, ToARN, Status string
	FromVersion, ToVersion     int32
	Created, Updated           time.Time
}
type Receipt struct {
	Scope
	Operation, Token, Hash, ARN string
	Version                     int32
}
type Reader interface {
	Context() context.Context
	Share(string) (Share, error)
	Shares() ([]Share, error)
	Invitation(string) (Invitation, error)
	Invitations() ([]Invitation, error)
	Permission(string) (Permission, error)
	Permissions() ([]Permission, error)
	Receipt(Scope, string, string) (Receipt, error)
	Replacements() ([]Replacement, error)
}
type Transaction interface {
	Reader
	PutShare(Share) error
	PutInvitation(Invitation) error
	PutPermission(Permission) error
	DeletePermission(string) error
	PutReceipt(Receipt) error
	PutReplacement(Replacement) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
