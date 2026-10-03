package account

import (
	"context"
	"time"
)

// RegionKey separates account settings by partition, account and target region.
type RegionKey struct{ Partition, AccountID, Region string }

// RegionRecord retains an accepted region transition. Reads project Status at
// Due; storage does not require a worker to make an elapsed transition visible.
type RegionRecord struct {
	Status RegionStatus
	Due    time.Time
}

type Reader interface {
	Context() context.Context
	Region(RegionKey) (RegionRecord, bool, error)
	Contact(Scope) (ContactInformation, bool, error)
	AlternateContact(AlternateContactKey) (AlternateContact, bool, error)
	PrimaryEmailUpdate(Scope) (PrimaryEmailUpdate, bool, error)
	PrimaryEmailUpdates() ([]PrimaryEmailUpdate, error)
}

type Writer interface {
	Reader
	PutRegion(RegionKey, RegionRecord) error
	PutContact(Scope, ContactInformation) error
	PutAlternateContact(AlternateContactKey, AlternateContact) error
	DeleteAlternateContact(AlternateContactKey) error
	PutPrimaryEmailUpdate(PrimaryEmailUpdate) error
}

// Repository callbacks are atomic and expire on return. Related IAM and
// Organizations reads join Reader.Context, keeping authorization and mutation
// in the same transaction. Errors and cancellation roll back every staged write.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Writer) error) error
}
