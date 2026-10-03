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

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
