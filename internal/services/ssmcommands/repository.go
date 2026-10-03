// Package ssmcommands owns managed-node registration and durable Run Command state.
// Customer programs execute only in the official agent, never in this controller.
package ssmcommands

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("managed execution record not found")

type Scope struct{ Partition, AccountID, Region string }
type Key struct {
	Scope
	ID string
}
type InvocationKey struct {
	Command Key
	NodeID  string
}

// Node retains agent observations. EC2 remains the authority for instance identity,
// lifecycle, network addresses, tags and instance profiles.
type Node struct {
	Key                                                                                Key
	AgentVersion, AgentName, PlatformType, PlatformName, PlatformVersion, ComputerName string
	RegisteredAt, LastPing                                                             time.Time
}

type Target struct {
	Key    string
	Values []string
}

// Command snapshots an admitted immutable document and its parameter values.
// Content is customer document source, not a serialized resource-state ledger.
type Command struct {
	Key                                                           Key
	DocumentName, DocumentVersion, DocumentHash, Content, Comment string
	Parameters                                                    map[string][]string
	InstanceIDs                                                   []string
	Targets                                                       []Target
	RequestedAt, DeliveryDeadline                                 time.Time
	// EmptyTargetReadyAt schedules completion only for admission with no resolved nodes.
	// Zero means this command has no empty-target lifecycle job.
	EmptyTargetReadyAt                                 time.Time
	TimeoutSeconds                                     int32
	MaxConcurrency, MaxErrors                          string
	Concurrency, ErrorBudget                           int
	OutputBucket, OutputPrefix, OutputRegion, LogGroup string
	CloudWatchEnabled                                  bool
	Status, StatusDetails                              string
	ParentEventID                                      string
	ServiceRoleARN, ServiceRoleID                      string
	NotificationARN, NotificationType                  string
	NotificationEvents                                 []string
	Alarm                                              *AlarmConfiguration
	AlarmPoll                                          AlarmPoll
}

// Invocation owns delivery and cancellation fences independently of plugin results.
// Stable message IDs survive reconnect; acknowledged work is never redelivered.
type Invocation struct {
	Key                                         InvocationKey
	InstanceName, Status, StatusDetails, Trace  string
	DeliveryID, CancelID, CancelJobID           string
	DeliveredAt, StartedAt, FinishedAt, RetryAt time.Time
	DeliveryAcknowledged, CancelAcknowledged    bool
	Plugins                                     []Plugin
	ReplyIDs                                    []string
}

type Plugin struct {
	Name, Action, Status, StatusDetails   string
	Code                                  int32
	Output, StandardOutput, StandardError string
	StartedAt, FinishedAt                 time.Time
	OutputBucket, OutputPrefix            string
}

type Reader interface {
	Context() context.Context
	Node(Key) (Node, error)
	Nodes(Scope) ([]Node, error)
	Command(Key) (Command, error)
	Commands(Scope) ([]Command, error)
	Invocation(InvocationKey) (Invocation, error)
	Invocations(Key) ([]Invocation, error)
	NodeInvocations(Key) ([]Invocation, error)
	NextDeadline() (Command, error)
	Notification(string) (Notification, error)
	NextNotification() (Notification, error)
	NextAlarmPoll() (Command, error)
	AlarmRegions(partition, account string) ([]string, error)
}
type Transaction interface {
	Reader
	PutNode(Node) error
	PutCommand(Command) error
	PutInvocation(Invocation) error
	PutNotification(Notification) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

// Instance is a current projection from the existing EC2 repository, not SSM state.
type Instance struct {
	ID, State, PrivateIP string
	Tags                 map[string]string
}
type Instances interface {
	Instance(context.Context, string) (Instance, error)
}

// Notification retains an observed transition, not a reconstruction of current
// status. ID and revision fence scheduler selections across retries and restart.
type Notification struct {
	ID, NodeID, Status, StatusDetails, MessageID, LastError string
	Command                                                 Key
	EventTime, Due, DeliveredAt                             time.Time
	Revision                                                uint64
}
