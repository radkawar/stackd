// Package resourcegroupstaggingapi provides the regional tag inventory over the
// resource owners. Tag values remain exclusively in the owning service.
package resourcegroupstaggingapi

import (
	"context"
	"time"

	"stackd/internal/awsctx"
)

// Scope identifies the account and Region in which inventory was observed.
type Scope struct{ Partition, AccountID, Region string }

// Resource is a transient owner snapshot, never a second authoritative record.
// ResourceType uses the Tagging API's service[:resourceType] spelling.
type Resource struct {
	ARN          string
	ResourceType string
	Tags         map[string]string
}

// Resources reads scoped typed owners without borrowing caller list permissions.
// Mutations MUST invoke the owner's ordinary authorization/transaction boundary.
// An empty service selects every owner; otherwise service is the AWS event-source
// prefix (ec2, ssm, monitoring, events, etc.).
type Resources interface {
	List(context.Context, string) ([]Resource, error)
	Tag(context.Context, Resource, map[string]string) error
	Untag(context.Context, Resource, []string) error
}

// Source permits an owner to expose scoped inventory without exposing its store.
type Source interface {
	ListTaggingResources(context.Context) ([]Resource, error)
}

// Membership retains only whether a live resource was previously tagged.
// Service groups entries by their native event-source prefix for reconciliation.
type Membership struct {
	Scope
	Service, ARN string
}

// Report retains only the latest export's delivery intent and outcome. Resource
// tags and policy snapshots are read from their owners, never persisted here.
// Version fences both replacement and a worker's renewable delivery lease.
type Report struct {
	Scope
	Version                                                 uint64
	OrganizationID, Bucket, ObjectKey, Status, ErrorMessage string
	StartedAt, CompletedAt, Due                             time.Time
	Caller                                                  awsctx.Metadata
}
type Reader interface {
	Context() context.Context
	Memberships(Scope, string) ([]Membership, error)
	Report(Scope) (Report, bool, error)
	NextReport() (Report, bool, error)
}
type Transaction interface {
	Reader
	PutMembership(Membership) error
	DeleteMembership(Membership) error
	PutReport(Report) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
