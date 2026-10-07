// Package cloudformation owns template evaluation and retained deployment work.
package cloudformation

import (
	"context"
	"errors"
	"time"

	"stackd/internal/awsctx"
)

var ErrNotFound = errors.New("cloudformation record not found")

type Scope struct{ Partition, Account, Region string }

type StackRecord struct {
	Scope                                       Scope
	ID, Name, Status, StatusReason, Description string
	Template, RoleARN, OperationID              string
	// NestedOwner binds an actual child stack to one parent resource incarnation.
	// Native and direct Cloud Control roots have no parent ownership metadata.
	NestedOwner, ParentID, RootID          string
	Created, Updated                       time.Time
	Deleted                                *time.Time
	Parameters, Tags                       map[string]string
	ResolvedParameters                     map[string]string
	Capabilities                           []string
	Outputs                                map[string]OutputValue
	Imports                                []string
	DisableRollback, TerminationProtection bool
	EventSequence                          uint64
}

type ResourceRecord struct {
	StackID, LogicalID, Type, PhysicalID, Ref, Token string
	Generation                                       uint64
	// Current selects the stack's logical incarnation, including deleted-stack
	// history; it does not assert that the owner's physical resource exists.
	Current                                                   bool
	Status, StatusReason, DeletionPolicy, UpdateReplacePolicy string
	Properties                                                Properties
	// EventProperties retains the NoEcho projection with this incarnation's
	// resolved properties, including cleanup after the stack template changes.
	EventProperties Properties
	Attributes      map[string]any
	Updated         time.Time
}

type EventRecord struct {
	StackID, ID, LogicalID, Type, PhysicalID, Status, Reason, Token string
	Sequence                                                        uint64
	Timestamp                                                       time.Time
	Properties                                                      Properties
}

// StepRecord retains the before-image and exact physical identity needed for
// restart and rollback. Effects themselves remain owned by the target service.
type StepRecord struct {
	Position                        int
	LogicalID, Action, State, Error string
	DeleteFailures                  int
	// BeforeDeleteStarted retains an intent whose owner effect may have happened
	// before a controller crash; rollback must observe the exact old identity.
	BeforeDeleteStarted bool
	// BeforeDeleted records irreversible delete-before-create progress so
	// rollback restores the previous owner instead of only deleting the new one.
	BeforeDeleted bool
	// AdmissionPending distinguishes a command explicitly not admitted by its
	// owner from a crash whose admitted result has not yet been retained.
	AdmissionPending bool
	Before, After    ResourceRecord
	// Restore is a fresh physical incarnation of Before, never an adopted or
	// resurrected repository row. Its token is durable before owner creation.
	Restore ResourceRecord
}

type OperationRecord struct {
	ID, StackID, Kind, Phase, Token, RequestHash, ChangeSetID, Reason string
	Template                                                          string
	Parameters, Tags                                                  map[string]string
	ResolvedParameters                                                map[string]string
	Capabilities                                                      []string
	RoleARN                                                           string
	Caller                                                            awsctx.Metadata
	Steps                                                             []StepRecord
	Cursor                                                            int
	Revision                                                          uint64
	Due, Started                                                      time.Time
	Cancel, DisableRollback                                           bool
}

type ChangeRecord struct {
	LogicalID, Type, Action, Replacement, PhysicalID string
	BeforeContext, AfterContext                      string
}

type ChangeSetRecord struct {
	Scope                                                                            Scope
	ID, Name, StackID, StackName, Type, Status, ExecutionStatus, Reason, Description string
	Template, RoleARN, Token, RequestHash                                            string
	Parameters, Tags                                                                 map[string]string
	ResolvedParameters                                                               map[string]string
	Capabilities                                                                     []string
	Changes                                                                          []ChangeRecord
	Created                                                                          time.Time
	DisableRollback                                                                  bool
}

type ExportRecord struct {
	Scope                Scope
	Name, Value, StackID string
}

// Reader ordering is part of the contract: stacks/changesets by ID, resources by
// logical ID then generation, events by descending sequence, exports by name.
type Reader interface {
	Context() context.Context
	Stack(string) (StackRecord, error)
	Stacks(Scope) ([]StackRecord, error)
	Resources(string) ([]ResourceRecord, error)
	Events(string) ([]EventRecord, error)
	Operation(string) (OperationRecord, error)
	NextOperation() (OperationRecord, bool, error)
	ChangeSet(string) (ChangeSetRecord, error)
	ChangeSets(string) ([]ChangeSetRecord, error)
	Exports(Scope) ([]ExportRecord, error)
}

type Transaction interface {
	Reader
	PutStack(StackRecord) error
	PutResource(ResourceRecord) error
	PutEvent(EventRecord) error
	PutOperation(OperationRecord) error
	PutChangeSet(ChangeSetRecord) error
	DeleteChangeSet(string) error
	PutExport(ExportRecord) error
	DeleteExport(Scope, string) error
}

type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
}
