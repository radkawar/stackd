// Package scheduler implements EventBridge Scheduler resources and retained work.
package scheduler

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("scheduler resource not found")

type Scope struct {
	Partition, Account, Region string
}

type GroupKey struct {
	Scope
	Name string
}

type ScheduleKey struct {
	Group GroupKey
	Name  string
}

func (k GroupKey) ARN() string {
	return "arn:" + k.Partition + ":scheduler:" + k.Region + ":" + k.Account + ":schedule-group/" + k.Name
}

func (k ScheduleKey) ARN() string {
	return "arn:" + k.Group.Partition + ":scheduler:" + k.Group.Region + ":" + k.Group.Account + ":schedule/" + k.Group.Name + "/" + k.Name
}

type GroupRecord struct {
	ID, CFNOwner      string
	Key               GroupKey
	Created, Modified time.Time
	Tags              map[string]string
	ClientToken       string
}

// TargetRecord owns configuration, not a serialized API request. Input is the
// customer's delivery payload; ciphertext replaces it when a CMK is configured.
type TargetRecord struct {
	ARN, RoleARN, Input, DeadLetterARN                         string
	HasInput                                                   bool
	MaxAgeSeconds, MaxRetries                                  int
	MessageGroupID, EventSource, EventDetailType, PartitionKey string
	HasSQS, HasEventBridge, HasKinesis                         bool
	ECS                                                        *ECSTarget
}

type ECSTarget struct {
	TaskDefinitionARN, Group, LaunchType, PlatformVersion, PropagateTags, ReferenceID string
	TaskCount                                                                         int
	HasTaskCount, ManagedTags, ExecuteCommand, HasManagedTags, HasExecuteCommand      bool
	HasNetwork                                                                        bool
	AssignPublicIP                                                                    string
	Subnets, SecurityGroups                                                           []string
	Capacity                                                                          []CapacityProvider
	Constraints                                                                       []PlacementConstraint
	Placement                                                                         []PlacementStrategy
	Tags                                                                              []Tag
}

type CapacityProvider struct {
	Name               string
	Base, Weight       int
	HasBase, HasWeight bool
}

type PlacementConstraint struct {
	Type, Expression string
}

type PlacementStrategy struct {
	Type, Field string
}

type Tag struct {
	Key, Value string
}

type ScheduleRecord struct {
	CFNOwner, ParentID                                              string
	Key                                                             ScheduleKey
	Created, Modified                                               time.Time
	Expression, Timezone, State, Description, ActionAfterCompletion string
	HasDescription                                                  bool
	Start, End, Next                                                *time.Time
	WindowMode                                                      string
	WindowMinutes                                                   int
	HasWindowMinutes                                                bool
	Target                                                          TargetRecord
	KmsKeyARN                                                       string
	Ciphertext, DataKey                                             []byte
	Revision                                                        uint64
	CreateToken, UpdateToken, CreateHash, UpdateHash                string
}

// DeliveryRecord is an immutable admitted occurrence plus mutable retry state.
// It does not reference the current schedule configuration: updates cannot
// rewrite work already admitted, and auto-deletion does not discard its retries.
type DeliveryRecord struct {
	ID                                     string
	Schedule                               ScheduleKey
	Revision                               uint64
	Scheduled, Due, Expires                time.Time
	Target                                 TargetRecord
	KmsKeyARN                              string
	Ciphertext, DataKey                    []byte
	Attempts                               int
	Phase, LastErrorCode, LastErrorMessage string
}

type Reader interface {
	Context() context.Context
	Group(GroupKey) (GroupRecord, error)
	Groups(Scope) ([]GroupRecord, error)
	Schedule(ScheduleKey) (ScheduleRecord, error)
	Schedules(Scope) ([]ScheduleRecord, error)
	NextSchedule() (ScheduleRecord, bool, error)
	Delivery(string) (DeliveryRecord, error)
	NextDelivery() (DeliveryRecord, bool, error)
}

type Transaction interface {
	Reader
	PutGroup(GroupRecord) error
	DeleteGroup(GroupKey) error
	PutSchedule(ScheduleRecord) error
	DeleteSchedule(ScheduleKey) error
	PutDelivery(DeliveryRecord) error
	DeleteDelivery(string) error
	DeleteScheduleDeliveries(ScheduleKey) error
	DeleteGroupDeliveries(GroupKey) error
}

type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
}
