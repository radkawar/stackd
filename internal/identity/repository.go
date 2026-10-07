package identity

import "context"

// Record is the credential aggregate persisted by a repository. Repository
// implementations must return detached values, including session collections.
type Record struct {
	Credential Credential
	Status     Status
	LastUsed   LastUsed
	// CloudFormationOwner is trusted incarnation metadata, never credential material.
	CloudFormationOwner string
}

// Reader is a consistent snapshot. FindPrincipal includes sessions issued for
// that principal as well as long-term keys, without requiring a full-store scan
// from a relational implementation.
type Reader interface {
	Get(accessKeyID string) (Record, error)
	FindPrincipal(accountID, principalID string) ([]Record, error)
}

// Transaction owns mutations until the enclosing Update commits successfully.
// Values passed to Put remain owned by the caller and must be copied.
type Transaction interface {
	Reader
	Put(Record) error
	Delete(accessKeyID string) error
}

// Repository isolates credential semantics from storage. View observes one
// consistent snapshot; Update is serializable and rolls back all writes when
// its callback or commit fails. Context cancellation before commit rolls back.
// Callbacks must not retain or concurrently use readers or transactions.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
}
