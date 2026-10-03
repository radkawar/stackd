// Package resourcegroups owns scoped resource group definitions and membership.
// The resource owners remain authoritative for existence, incarnation and tags.
package resourcegroups

import (
	"context"
	api "stackd/internal/awsapi/resourcegroups"
	"time"
)

type Scope struct{ Partition, AccountID, Region string }

type Group struct {
	Scope
	ARN, Name, Description string
	Incarnation            string
	DisplayName, Owner     string
	Criticality            *int32
	Query                  *api.ResourceQuery
	Tags                   map[string]string
	Created                time.Time
	// ManagedType is set only by the owning AppRegistry application.
	ManagedType, ApplicationARN, SourceARN, SourceName, ParentARN string
}

// Grouping records an admitted owner transition, fenced to that incarnation.
// Query membership still reads the owner's current tags.
type Grouping struct {
	GroupARN, ResourceARN, ResourceType, Incarnation, Action string
	Status                                                   string
	ErrorCode, ErrorMessage                                  string
	// TaskARN is empty for a direct grouping action, which takes ownership
	// from a prior tag-sync effect even when the tag value is unchanged.
	TaskARN string
	Updated time.Time
}

type Reader interface {
	JobReader
	Context() context.Context
	Group(Scope, string) (Group, bool, error)
	Groups(Scope) ([]Group, error)
	Groupings(string) ([]Grouping, error)
}
type Transaction interface {
	JobWriter
	Reader
	PutGroup(Group) error
	DeleteGroup(Scope, string) error
	PutGrouping(Grouping) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
