// Package applicationautoscaling owns scalable targets, policies, schedules and activities.
package applicationautoscaling

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/applicationautoscaling"
)

var ErrNotFound = errors.New("application auto scaling resource not found")

type Scope struct{ Partition, AccountID, Region string }

type TargetKey struct {
	Scope
	Namespace, ResourceID, Dimension string
}

// Data is the generated public resource, not a second wire model. Tags belong
// only to targets. ReconcileAt owns asynchronous min/max enforcement after a
// target update; service capacity itself remains in the resource's repository.
type TargetRecord struct {
	// ID owns the target identity also present in native child policy/action ARNs.
	ID            string
	Ownership     string
	Key           TargetKey
	Data          api.ScalableTarget
	Tags          api.TagMap
	OriginEventID string
	ReconcileAt   time.Time
}

type PolicyKey struct {
	TargetKey
	Name string
}

// LastScale records completed capacity and the cumulative credit of an active
// scale-out cooldown. PendingActivityID links accepted intent to the activity
// that owns its capacity baseline. ManagedActionID is the native action suffix.
type PolicyRecord struct {
	Key                        PolicyKey
	Ownership                  string
	Data                       api.ScalingPolicy
	ManagedActionID            string
	LastScaleAt                time.Time
	LastScaleFrom, LastScaleTo int32
	PendingActivityID          string
}

type ScheduleKey struct {
	TargetKey
	Name string
}

type ScheduleRecord struct {
	Key           ScheduleKey
	Data          api.ScheduledAction
	OriginEventID string
	NextDue       time.Time
}

type ActivityKey struct {
	Scope
	ID string
}

// ActivityRecord retains history independently of the target's lifetime. The
// generated resource owns its public identity and state; From and To retain the
// capacity baseline needed to complete accepted work and start policy cooldowns.
// The repository assigns Sequence on first insertion and preserves it on updates.
type ActivityRecord struct {
	Key           ActivityKey
	Data          api.ScalingActivity
	Sequence      int64
	PolicyName    string
	OriginEventID string
	From, To      int32
}

// ActivityCursor orders the next unreturned activity by descending start time,
// with insertion sequence breaking ties when service time has not advanced.
type ActivityCursor struct {
	StartTime time.Time
	Sequence  int64
}

type ActivityQuery struct {
	Scope
	Namespace, ResourceID, Dimension string
	Since                            time.Time
	IncludeNotScaled                 bool
	From                             *ActivityCursor
	Limit                            int
}

// ListCursor is the next unreturned key within a query's scope and namespace.
// Keyset continuation does not depend on the continued record still existing.
type ListCursor struct {
	ResourceID, Dimension, Name string
}

// Queries select one scope and namespace; other empty filters are unrestricted.
// Commands own public pagination admission; a zero Limit means unrestricted.
type TargetQuery struct {
	Scope
	Namespace, Dimension string
	ResourceIDs          []string
	Limit                int
	From                 *ListCursor
}

type PolicyQuery struct {
	Scope
	Namespace, ResourceID, Dimension string
	// Names select in caller order; duplicate names use their first position.
	Names []string
	Limit int
	From  *ListCursor
}

type ScheduleQuery struct {
	Scope
	Namespace, ResourceID, Dimension string
	Names                            []string
	Limit                            int
	From                             *ListCursor
}

type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	// Attempt isolates a recoverable command while the caller owns its deadline.
	Attempt(context.Context, func(Transaction) error) error
}

type Reader interface {
	Context() context.Context
	Target(TargetKey) (TargetRecord, error)
	TargetByARN(Scope, string) (TargetRecord, error)
	Targets(TargetQuery) ([]TargetRecord, error)
	// TargetKeys spans all regions for a linked-role usage decision.
	TargetKeys(partition, accountID string) ([]TargetKey, error)
	Policy(PolicyKey) (PolicyRecord, error)
	Policies(PolicyQuery) ([]PolicyRecord, error)
	Schedule(ScheduleKey) (ScheduleRecord, error)
	Schedules(ScheduleQuery) ([]ScheduleRecord, error)
	Activities(ActivityQuery) ([]ActivityRecord, error)
	// PendingActivities returns Pending and InProgress work for lifecycle observation.
	PendingActivities(TargetKey) ([]ActivityRecord, error)
	// NextPendingActivity selects the oldest Pending command, not InProgress work.
	NextPendingActivity() (ActivityRecord, bool, error)
	NextTargetReconcile() (TargetKey, time.Time, bool, error)
	NextSchedule() (ScheduleKey, time.Time, bool, error)
}

type Transaction interface {
	Reader
	PutTarget(TargetRecord) error
	// DeleteTarget also removes its policies, schedules and tags. The command
	// removes owned CloudWatch alarms in the same shared transaction.
	DeleteTarget(TargetKey) error
	PutPolicy(PolicyRecord) error
	DeletePolicy(PolicyKey) error
	PutSchedule(ScheduleRecord) error
	DeleteSchedule(ScheduleKey) error
	PutActivity(ActivityRecord) error
	DeleteActivitiesBefore(Scope, time.Time) error
}
