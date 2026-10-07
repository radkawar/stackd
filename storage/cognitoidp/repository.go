// Package cognitoidp exposes service-owned Cognito user pool storage contracts.
package cognitoidp

import (
	domain "stackd/internal/services/cognitoidp"
	"stackd/storage/memory"
)

type (
	Repository       = domain.Repository
	Reader           = domain.Reader
	Transaction      = domain.Transaction
	Scope            = domain.Scope
	PoolKey          = domain.PoolKey
	OwnershipKey     = domain.OwnershipKey
	OwnershipRecord  = domain.OwnershipRecord
	ResourceOwner    = domain.ResourceOwner
	ProviderKey      = domain.ProviderKey
	ProviderRecord   = domain.ProviderRecord
	OAuthKey         = domain.OAuthKey
	OAuthRecord      = domain.OAuthRecord
	ClientKey        = domain.ClientKey
	UserKey          = domain.UserKey
	GroupKey         = domain.GroupKey
	ChallengeKey     = domain.ChallengeKey
	EmailCodeKey     = domain.EmailCodeKey
	EmailCodeRecord  = domain.EmailCodeRecord
	SessionKey       = domain.SessionKey
	SigningKey       = domain.SigningKey
	PoolSigningKeys  = domain.PoolSigningKeys
	PoolRecord       = domain.PoolRecord
	ClientRecord     = domain.ClientRecord
	PasswordVerifier = domain.PasswordVerifier
	UserRecord       = domain.UserRecord
	GroupRecord      = domain.GroupRecord
	ChallengeRecord  = domain.ChallengeRecord
	SessionRecord    = domain.SessionRecord
)

const (
	OwnerKindClient      = domain.OwnerKindClient
	OwnerKindClientToken = domain.OwnerKindClientToken
	OwnerKindUser        = domain.OwnerKindUser
	OwnerKindGroup       = domain.OwnerKindGroup
	OwnerKindProvider    = domain.OwnerKindProvider
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
