// Package autoscaling owns EC2 Auto Scaling groups and their instance lifecycle.
package autoscaling

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/autoscaling"
)

var ErrNotFound = errors.New("auto scaling resource not found")

type Scope struct{ Partition, AccountID, Region string }
type GroupKey struct {
	Scope
	Name string
}

// GroupRecord owns desired state. Instances, hooks and activities have their own
// typed records; Data.Instances is assembled only for the public description.
// ID is the ARN incarnation, and survives a change to any mutable group setting.
type GroupRecord struct {
	Key                   GroupKey
	Ownership             string
	ID                    string
	Data                  api.AutoScalingGroup
	OriginEventID         string
	ReconcileCause        string
	PendingInstanceWarmup *int32
	Deleting              bool
	ReconcileAt           time.Time
	MetricAt              time.Time
	Version               uint64
	// ScaleUpVersion advances only when an existing group's desired capacity increases.
	ScaleUpVersion uint64
}

// InstanceRecord is membership, not EC2 state. The EC2 owner remains authoritative
// for execution, networking, credentials and storage. An instance retains its
// admitted launch version even when the group's template subsequently changes.
// TerminationRequested identifies an admitted, unfinished termination; retention
// cancels that intent while preserving membership in Terminating:Retained.
type InstanceRecord struct {
	Group                   GroupKey
	GroupID                 string
	Data                    api.Instance
	JoinedAt                time.Time
	InServiceAt             time.Time
	WarmUntil               time.Time
	ActivityID              string
	TerminationRequested    bool
	DetachRequested         bool
	HealthCheckGraceIgnored bool
}

type ActivityKey struct {
	Scope
	ID string
}

// ActivityRecord is the native-visible work intent and recovery owner. Launches
// reuse its ID as the EC2 ClientToken, rather than adding a second receipt ledger.
// The selected numeric template version, subnet, and warm-pool power destination
// do not change during retry.
type ActivityRecord struct {
	Key                  ActivityKey
	Group                GroupKey
	GroupID              string
	Data                 api.Activity
	Kind                 string
	InstanceID           string
	SubnetID             string
	LaunchTemplate       api.LaunchTemplateSpecification
	InstanceWarmup       *int32
	LaunchTags           api.TagDescriptionList
	ProtectedFromScaleIn bool
	WarmPoolState        string
	OriginEventID        string
	RetryAt              time.Time
}

type PolicyKey struct {
	GroupKey
	Name string
}
type PolicyRecord struct {
	Key         PolicyKey
	Ownership   string
	GroupID     string
	Data        api.ScalingPolicy
	LastScaleAt time.Time
}

type ScheduleKey struct {
	GroupKey
	Name string
}
type ScheduleRecord struct {
	Key           ScheduleKey
	Ownership     string
	GroupID       string
	Data          api.ScheduledUpdateGroupAction
	NextDue       time.Time
	OriginEventID string
}

type HookKey struct {
	GroupKey
	Name string
}
type HookRecord struct {
	Key       HookKey
	Ownership string
	GroupID   string
	Data      api.LifecycleHook
}

// LifecycleAction retains the consumer-visible token and both deadlines. A
// heartbeat extends the heartbeat deadline, never the action's global lifetime.
type LifecycleAction struct {
	Group                                            GroupKey
	GroupID, Token, HookName, InstanceID, Transition string
	DefaultResult                                    string
	HeartbeatTimeout                                 time.Duration
	Deadline, GlobalDeadline                         time.Time
	OriginEventID                                    string
}

// RefreshRecord owns a rolling deployment and its native history. Members are
// the original replacement cohort, not a work ledger: admitted EC2 effects remain
// owned by ActivityRecord and current membership.
type RefreshRecord struct {
	Group                GroupKey
	GroupID              string
	Data                 api.InstanceRefresh
	Original             api.LaunchTemplateSpecification
	Target               api.LaunchTemplateSpecification
	Members              []RefreshMember
	OriginEventID        string
	RequestedAt          time.Time
	BlockedSince         time.Time
	PauseUntil           time.Time
	ActiveDeadline       time.Time
	Checkpoint           int
	WaitForTransitioning bool
}

type RefreshMember struct {
	InstanceID string
	Warm       bool
}

type GroupQuery struct {
	Scope
	Names []string
	After string
	Limit int
}

type GroupWork struct {
	Key      GroupKey
	ID       string
	Version  uint64
	Due      time.Time
	MetricAt time.Time
	Deleting bool
}

type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

type Reader interface {
	Context() context.Context
	Group(GroupKey) (GroupRecord, error)
	Groups(GroupQuery) ([]GroupRecord, error)
	PendingGroups() ([]GroupWork, error)
	GroupKeys(partition, accountID string) ([]GroupKey, error)
	Instances(GroupKey) ([]InstanceRecord, error)
	Instance(Scope, string) (InstanceRecord, error)
	Activity(ActivityKey) (ActivityRecord, error)
	Activities(Scope, string, bool) ([]ActivityRecord, error)
	Policy(PolicyKey) (PolicyRecord, error)
	Policies(GroupKey) ([]PolicyRecord, error)
	Schedule(ScheduleKey) (ScheduleRecord, error)
	Schedules(GroupKey) ([]ScheduleRecord, error)
	PendingSchedules() ([]ScheduleRecord, error)
	Hook(HookKey) (HookRecord, error)
	Hooks(GroupKey) ([]HookRecord, error)
	LifecycleActions(GroupKey) ([]LifecycleAction, error)
	PendingLifecycleActions() ([]LifecycleAction, error)
	Refreshes(GroupKey) ([]RefreshRecord, error)
}

type Transaction interface {
	Reader
	PutGroup(GroupRecord) error
	DeleteGroup(GroupKey) error
	PutInstance(InstanceRecord) error
	DeleteInstance(Scope, string) error
	PutActivity(ActivityRecord) error
	DeleteActivitiesBefore(Scope, time.Time) error
	PutPolicy(PolicyRecord) error
	DeletePolicy(PolicyKey) error
	PutSchedule(ScheduleRecord) error
	DeleteSchedule(ScheduleKey) error
	PutHook(HookRecord) error
	DeleteHook(HookKey) error
	PutLifecycleAction(LifecycleAction) error
	DeleteLifecycleAction(GroupKey, string) error
	PutRefresh(RefreshRecord) error
}
