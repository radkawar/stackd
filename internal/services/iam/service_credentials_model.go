package iam

import (
	"context"
	"errors"
	"time"

	"stackd/internal/identity"
)

// ServiceCredentialRecord binds a generated service secret to an immutable IAM
// user. Only a digest of the cryptographically random secret is persisted.
type ServiceCredentialRecord struct {
	ID                     string
	UserID                 string
	ServiceName            string
	ServiceUserName        string
	ServiceCredentialAlias string
	Status                 string
	CreateDate             time.Time
	ExpirationDate         *time.Time
	CredentialAgeDays      int64
	SecretDigest           [32]byte
	Slot                   int
}

var ErrInvalidServiceCredential = errors.New("invalid service-specific credential")

// ServiceCredentialVerifier authenticates a secret for one service and returns
// its current IAM identity. Consumers must still authorize the requested action
// against that identity's current policies, boundary and organization controls.
// identifier is the service username or credential alias, not an IAM username.
// It may be empty for API-key credentials whose entire secret is a bearer token.
type ServiceCredentialVerifier interface {
	VerifyServiceCredential(ctx context.Context, scope Scope, service, identifier, secret string) (identity.Principal, error)
}

func cloneServiceCredential(record ServiceCredentialRecord) ServiceCredentialRecord {
	if record.ExpirationDate != nil {
		date := *record.ExpirationDate
		record.ExpirationDate = &date
	}
	return record
}
