package resourcegroups

import (
	"context"
	api "stackd/internal/awsapi/resourcegroups"
	"stackd/internal/services/eventbridge"
	"time"
)

// Roles resolves current trust on every execution, never cached deployment rights.
type Roles interface {
	EnsureLifecycleRole(context.Context) error
	AssumeLifecycleRole(context.Context, Scope) (context.Context, error)
	AssumeTagSyncRole(context.Context, string, string) (context.Context, error)
}
type LifecyclePublisher interface {
	PublishEvent(context.Context, eventbridge.EventRecord) error
}

// TagSyncTask retains the original selector and its normalized evaluation query.
type TagSyncTask struct {
	Scope
	ARN, GroupARN, GroupName, RoleARN string
	Query                             api.ResourceQuery
	TagKey, TagValue                  string
	UsesTag                           bool
	Status, ErrorMessage              string
	Created, NextCheck                time.Time
	Version                           uint64
}

// AppliedMembership is ownership of an effect, not merely query membership.
// An existing direct awsApplication tag never creates one of these records.
type AppliedMembership struct {
	TaskARN, ResourceARN, ResourceType, Incarnation string
	AppliedAt                                       time.Time
}
type LifecycleAccount struct {
	Initialized bool
	Scope
	Desired, Status, Message string
	NextCheck                time.Time
	Version                  uint64
}
type LifecycleMember struct{ ARN, Type, Incarnation string }

// LifecycleSnapshot survives group deletion until its delete event commits.
type LifecycleSnapshot struct {
	Group    Group
	Sequence uint64
	Members  []LifecycleMember
}
type JobReader interface {
	TagSyncTasks() ([]TagSyncTask, error)
	AppliedMemberships(string) ([]AppliedMembership, error)
	LifecycleAccounts() ([]LifecycleAccount, error)
	LifecycleSnapshots(Scope) ([]LifecycleSnapshot, error)
}
type JobWriter interface {
	PutTagSyncTask(TagSyncTask) error
	DeleteTagSyncTask(string) error
	PutAppliedMembership(AppliedMembership) error
	DeleteAppliedMembership(string, string) error
	PutLifecycleAccount(LifecycleAccount) error
	PutLifecycleSnapshot(LifecycleSnapshot) error
	DeleteLifecycleSnapshot(string) error
}
