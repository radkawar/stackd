// Package stepfunctions exposes service-owned Step Functions storage contracts.
package stepfunctions

import (
	domain "stackd/internal/services/stepfunctions"
	"stackd/storage/memory"
)

type (
	Repository         = domain.Repository
	Reader             = domain.Reader
	Transaction        = domain.Transaction
	Scope              = domain.Scope
	MachineKey         = domain.MachineKey
	MachineRecord      = domain.MachineRecord
	RevisionKey        = domain.RevisionKey
	RevisionRecord     = domain.RevisionRecord
	VersionKey         = domain.VersionKey
	VersionRecord      = domain.VersionRecord
	AliasKey           = domain.AliasKey
	AliasRoute         = domain.AliasRoute
	AliasRecord        = domain.AliasRecord
	ActivityKey        = domain.ActivityKey
	ActivityRecord     = domain.ActivityRecord
	ExecutionKey       = domain.ExecutionKey
	ExecutionRecord    = domain.ExecutionRecord
	ExecutionSelection = domain.ExecutionSelection
	RedriveRequest     = domain.RedriveRequest
	FrameKey           = domain.FrameKey
	FramePhase         = domain.FramePhase
	FrameRecord        = domain.FrameRecord
	TaskKey            = domain.TaskKey
	TaskStatus         = domain.TaskStatus
	TaskRecord         = domain.TaskRecord
	HistoryRecord      = domain.HistoryRecord
	MapRunKey          = domain.MapRunKey
	MapRunRecord       = domain.MapRunRecord
	MapResultFile      = domain.MapResultFile
	WorkKind           = domain.WorkKind
	WorkRecord         = domain.WorkRecord
)

const (
	FrameReady    = domain.FrameReady
	FrameRedrive  = domain.FrameRedrive
	FrameWaiting  = domain.FrameWaiting
	FrameTask     = domain.FrameTask
	FrameJoining  = domain.FrameJoining
	FrameComplete = domain.FrameComplete
	FrameFailed   = domain.FrameFailed
	FrameAborted  = domain.FrameAborted

	TaskScheduled = domain.TaskScheduled
	TaskRunning   = domain.TaskRunning
	TaskSubmitted = domain.TaskSubmitted
	TaskSucceeded = domain.TaskSucceeded
	TaskFailed    = domain.TaskFailed
	TaskTimedOut  = domain.TaskTimedOut
	TaskCancelled = domain.TaskCancelled

	WorkMachineDelete    = domain.WorkMachineDelete
	WorkExecutionTimeout = domain.WorkExecutionTimeout
	WorkExecutionExpiry  = domain.WorkExecutionExpiry
	WorkFrame            = domain.WorkFrame
	WorkTaskDispatch     = domain.WorkTaskDispatch
	WorkTaskTimeout      = domain.WorkTaskTimeout
	WorkHeartbeatTimeout = domain.WorkHeartbeatTimeout
	WorkHistoryDelivery  = domain.WorkHistoryDelivery
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
