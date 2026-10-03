// Package stepfunctions owns workflow resources and retained ASL execution.
package stepfunctions

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("step functions resource not found")

// Scope is the regional owner of a workflow resource.
type Scope struct {
	Partition string
	AccountID string
	Region    string
}

type MachineKey struct {
	Scope
	Name string
}

// MachineRecord identifies the current incarnation of an unqualified ARN.
// Executions and versions pin immutable revisions, not this mutable pointer.
type MachineRecord struct {
	Key                     MachineKey
	ID                      string
	RevisionID              string
	Type                    string
	Status                  string
	Created                 time.Time
	Version                 int64
	DeleteAt                *time.Time
	NextVersion             int64
	FirstVersionDescription string
	Tags                    map[string]string
}

type RevisionKey struct {
	Scope
	ID string
}

// RevisionRecord is immutable admitted configuration. It remains available to
// executions after update or deletion of the machine, version or alias.
type RevisionRecord struct {
	EncryptionConfig
	Key        RevisionKey
	Machine    MachineKey
	MachineID  string
	Created    time.Time
	Definition string
	// DefinitionIdentity supports Create idempotency without granting read
	// authority over an encrypted definition. It is not an integrity check.
	DefinitionIdentity   string
	NeedsNestedSync      bool
	NeedsECSSync         bool
	RoleARN              string
	LogGroupARN          string
	Initial              bool
	LogLevel             string
	IncludeExecutionData bool
	TracingEnabled       bool
	Encrypted            *EncryptedPayload
}

type VersionKey struct {
	Machine   MachineKey
	MachineID string
	Number    int64
}

type VersionRecord struct {
	Key         VersionKey
	RevisionID  string
	Created     time.Time
	Description string
}

type AliasKey struct {
	Machine   MachineKey
	MachineID string
	Name      string
}

type AliasRoute struct {
	Version int64
	Weight  int32
}

type AliasRecord struct {
	Key         AliasKey
	Description string
	Created     time.Time
	Updated     time.Time
	Routes      []AliasRoute
}

type ActivityKey struct {
	Scope
	Name string
}

type ActivityRecord struct {
	EncryptionConfig
	Key     ActivityKey
	ID      string
	Created time.Time
	Tags    map[string]string
}

// Repository joins resource changes, execution transitions and source events in
// the configured transaction domain. External task effects run outside callbacks.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

type Reader interface {
	Context() context.Context
	Machine(MachineKey) (MachineRecord, error)
	Machines(Scope) ([]MachineRecord, error)
	MachineCount(Scope) (int64, error)
	Revision(RevisionKey) (RevisionRecord, error)
	Version(VersionKey) (VersionRecord, error)
	Versions(MachineKey, string) ([]VersionRecord, error)
	Alias(AliasKey) (AliasRecord, error)
	Aliases(MachineKey, string) ([]AliasRecord, error)
	Activity(ActivityKey) (ActivityRecord, error)
	Activities(Scope) ([]ActivityRecord, error)
	ActivityCount(Scope) (int64, error)
	Execution(ExecutionKey) (ExecutionRecord, error)
	Executions(ExecutionSelection) ([]ExecutionRecord, error)
	OpenExecutionCount(Scope) (int64, error)
	RedriveRequests(ExecutionKey) ([]RedriveRequest, error)
	Frame(FrameKey) (FrameRecord, error)
	Frames(ExecutionKey) ([]FrameRecord, error)
	Task(TaskKey) (TaskRecord, error)
	TaskByToken(Scope, string) (TaskRecord, error)
	ActivityTasks(ActivityKey) ([]TaskRecord, error)
	RecoverableTasks() ([]TaskRecord, error)
	History(ExecutionKey) ([]HistoryRecord, error)
	HistoryEvent(ExecutionKey, int64) (HistoryRecord, error)
	MapRun(MapRunKey) (MapRunRecord, error)
	MapRuns(ExecutionKey) ([]MapRunRecord, error)
	MapResultFiles(MapRunKey) ([]MapResultFile, error)
	NextWork() (WorkRecord, error)
}

type Transaction interface {
	Reader
	PutMachine(MachineRecord) error
	DeleteMachine(MachineKey) error
	PutRevision(RevisionRecord) error
	PutVersion(VersionRecord) error
	DeleteVersion(VersionKey) error
	PutAlias(AliasRecord) error
	DeleteAlias(AliasKey) error
	PutActivity(ActivityRecord) error
	DeleteActivity(ActivityKey) error
	PutExecution(ExecutionRecord) error
	DeleteExecution(ExecutionKey) error
	PutRedriveRequests(ExecutionKey, []RedriveRequest) error
	PutFrame(FrameRecord) error
	PutTask(TaskRecord) error
	AppendHistory(HistoryRecord) error
	PutMapRun(MapRunRecord) error
	PutMapResultFile(MapRunKey, MapResultFile) error
}
