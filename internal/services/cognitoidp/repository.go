// Package cognitoidp owns regional user pools and their authentication state.
package cognitoidp

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/cognitoidp"
)

var ErrNotFound = errors.New("cognito resource not found")

type Scope struct{ Partition, AccountID, Region string }
type PoolKey struct {
	Scope
	ID string
}
type ClientKey struct {
	PoolKey
	ID string
}
type UserKey struct {
	PoolKey
	Username string
}
type GroupKey struct {
	PoolKey
	Name string
}
type ChallengeKey struct {
	PoolKey
	Token string
}

// SessionKey.ID is the native authentication event_id retained across refreshes.
type SessionKey struct {
	PoolKey
	ID string
}

func (k PoolKey) ARN() string {
	return "arn:" + k.Partition + ":cognito-idp:" + k.Region + ":" + k.AccountID + ":userpool/" + k.ID
}

// SigningKey keeps private key material separate from public pool configuration.
type SigningKey struct {
	ID       string
	PKCS8DER []byte
}
type PoolSigningKeys struct{ Access, ID SigningKey }
type PoolRecord struct {
	Key                     PoolKey
	Data                    api.UserPoolType
	IssuerURL               string
	SoftwareTokenMFAEnabled bool
}
type ClientRecord struct {
	Key  ClientKey
	Data api.UserPoolClientType
}
type GroupRecord struct {
	Key  GroupKey
	Data api.GroupType
}

// PasswordVerifier is the Cognito SRP verifier, not a retained plaintext password.
// Direct password authentication checks the same verifier used by SRP.
type PasswordVerifier struct{ Salt, Verifier []byte }
type UserRecord struct {
	Key                         UserKey
	Data                        api.UserType
	Password                    PasswordVerifier
	PasswordExpires             *time.Time
	SoftwareTokenSecret         string
	SoftwareTokenPendingSecret  string
	SoftwareTokenPendingExpires time.Time
	SoftwareTokenLastCounter    int64
	SoftwareTokenEnabled        bool
	SoftwareTokenPreferred      bool
	SoftwareTokenDeviceName     string
}

// ChallengeRecord retains an issued, single-use authentication challenge.
// SRP uses its returned SECRET_BLOCK as Token because PASSWORD_VERIFIER has no
// Session response member. Other challenges expose Token as Session.
type ChallengeRecord struct {
	Key                      ChallengeKey
	ClientID, Username, Kind string
	Expires                  time.Time
	SRPPrivate               []byte
	SoftwareTokenSecret      string
	SoftwareTokenVerified    bool
}

// EmailCodeRecord belongs to a user, not the app client that requested delivery.
type EmailCodeKey struct {
	UserKey
	Kind string
}
type EmailCodeRecord struct {
	Key     EmailCodeKey
	Expires time.Time
	Digest  []byte
}

// SessionRecord is an authentication/refresh family. Revoked families retain
// user attribution for rejected token calls; offline JWT verification is unchanged.
type SessionRecord struct {
	Key                          SessionKey
	ClientID, Username, OriginID string
	// RefreshOriginID identifies the current token generation. Nonrotating
	// refresh emits it instead of the original family's OriginID.
	RefreshOriginID          string
	AuthTime, RefreshExpires time.Time
	RefreshDigest            []byte
	PreviousRefreshDigest    []byte
	RefreshGraceExpires      time.Time
	// Revoked invalidates refresh and family-origin JWTs. Global revocation
	// also invalidates generation-origin JWTs issued after disabling rotation.
	Revoked                bool
	GloballyRevoked        bool
	OAuthScope, OAuthNonce string
}

// Reader returns detached records and borrows the shared transaction context.
// Public lookups have a trusted partition/Region but no IAM account identity;
// the client or token identifies the actual owner account.
type Reader interface {
	Context() context.Context
	Pool(PoolKey) (PoolRecord, error)
	PoolByID(partition, region, id string) (PoolRecord, error)
	// PoolByDomain resolves a prefix domain, which is unique in a Region
	// across accounts.
	PoolByDomain(partition, region, domain string) (PoolRecord, error)
	PoolsForAccount(partition, accountID string) ([]PoolRecord, error)
	Pools(Scope) ([]PoolRecord, error)
	SigningKeys(PoolKey) (PoolSigningKeys, error)
	Client(ClientKey) (ClientRecord, error)
	ClientByID(partition, region, id string) (ClientRecord, error)
	// ClientsByID resolves a public bearer client ID across a partition.
	ClientsByID(partition, id string) ([]ClientRecord, error)
	Clients(PoolKey) ([]ClientRecord, error)
	User(UserKey) (UserRecord, error)
	UsersByAttribute(PoolKey, string, string) ([]UserRecord, error)
	Users(PoolKey) ([]UserRecord, error)
	Group(GroupKey) (GroupRecord, error)
	Groups(PoolKey) ([]GroupRecord, error)
	GroupsForUser(UserKey) ([]GroupRecord, error)
	UsersInGroup(GroupKey) ([]UserRecord, error)
	Challenge(ChallengeKey) (ChallengeRecord, error)
	EmailCode(EmailCodeKey) (EmailCodeRecord, error)
	Session(SessionKey) (SessionRecord, error)
	// Historical refresh tokens retain family ownership for revocation and
	// rejected-call attribution. The service decides current/grace acceptance.
	SessionByRefresh(PoolKey, string, []byte) (SessionRecord, error)
	// Ownership returns a CloudFormation incarnation claim on a pool child.
	Ownership(OwnershipKey) (OwnershipRecord, error)
	// PoolOwnership returns the pool claim of one exact incarnation in a scope.
	PoolOwnership(Scope, ResourceOwner) (OwnershipRecord, error)
	Provider(ProviderKey) (ProviderRecord, error)
	Providers(PoolKey) ([]ProviderRecord, error)
	OAuth(OAuthKey) (OAuthRecord, error)
}

// Pool/client deletion removes owned authentication state. User deletion removes
// attributes, memberships and challenges, but revokes and retains refresh families
// so rejected token calls can still resolve their username for audit attribution.
// Deleting a pool, client, user, group, membership or identity provider also
// removes the ownership claims naming it; a claim never outlives its resource.
type Transaction interface {
	Reader
	PutPool(PoolRecord) error
	PutSigningKeys(PoolKey, PoolSigningKeys) error
	DeletePool(PoolKey) error
	PutClient(ClientRecord) error
	DeleteClient(ClientKey) error
	PutUser(UserRecord) error
	DeleteUser(UserKey) error
	PutGroup(GroupRecord) error
	DeleteGroup(GroupKey) error
	AddGroupUser(GroupKey, string) error
	RemoveGroupUser(GroupKey, string) error
	PutChallenge(ChallengeRecord) error
	DeleteChallenge(ChallengeKey) error
	PutEmailCode(EmailCodeRecord) error
	DeleteEmailCode(EmailCodeKey) error
	PutSession(SessionRecord) error
	RevokeUserSessions(UserKey) error
	PutOwnership(OwnershipRecord) error
	DeleteOwnership(OwnershipKey) error
	PutProvider(ProviderRecord) error
	DeleteProvider(ProviderKey) error
	PutOAuth(OAuthRecord) error
	DeleteOAuth(OAuthKey) error
	DeleteExpiredOAuth(PoolKey, time.Time) error
}

type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
