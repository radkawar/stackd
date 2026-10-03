package stepfunctions

import (
	"time"

	api "stackd/internal/awsapi/stepfunctions"
)

type ExecutionKey struct {
	Scope
	ARN string
}

// ExecutionRecord pins admission and owns terminal status, history sequence and
// the workflow deadline. A frame or task cannot independently end an execution.
type ExecutionRecord struct {
	Key                ExecutionKey
	Machine            MachineKey
	MachineID          string
	RevisionID         string
	Name               string
	Type               string
	VersionARN         string
	AliasARN           string
	MapRunARN          string
	MapItemCount       int64
	MapGeneration      int64
	ParentEventID      string
	TraceHeader        string
	TraceSegmentID     string
	Status             string
	Input              string
	Output             string
	Error              string
	Cause              string
	Encrypted          *EncryptedPayload
	PeakMemoryBytes    int64
	Started            time.Time
	Stopped            *time.Time
	Deadline           time.Time
	Expires            *time.Time
	RedriveCount       int64
	Redriven           *time.Time
	Version            int64
	NextFrameID        int64
	NextHistoryID      int64
	DeliveredHistoryID int64
}

// RedriveRequest retains the native, bounded client-token idempotency window.
type RedriveRequest struct {
	Token string
	Count int64
	Date  time.Time
}

type ExecutionSelection struct {
	Scope
	MachineID  string
	VersionARN string
	AliasARN   string
	MapRunARN  string
	Status     string
}

type FrameKey struct {
	Execution ExecutionKey
	ID        int64
}

type FramePhase string

const (
	FrameReady    FramePhase = "READY"
	FrameRedrive  FramePhase = "REDRIVE"
	FrameWaiting  FramePhase = "WAITING"
	FrameTask     FramePhase = "TASK"
	FrameJoining  FramePhase = "JOINING"
	FrameComplete FramePhase = "COMPLETE"
	FrameFailed   FramePhase = "FAILED"
	FrameAborted  FramePhase = "ABORTED"
)

// FrameRecord is one sequential ASL scope, including a Parallel branch or Map
// iteration. Input/Variables/Arguments/Output are customer JSON documents, not
// serialized resource records. Retriers belong to the current state entry.
type FrameRecord struct {
	Key               FrameKey
	ParentID          int64
	ParentStateID     int64
	ParentAttempt     int64
	BranchIndex       int64
	ScopePath         string
	StateName         string
	Phase             FramePhase
	Input             string
	Variables         string
	Arguments         string
	Output            string
	Error             string
	Cause             string
	Encrypted         *EncryptedPayload
	Entered           time.Time
	StartedHistoryID  int64
	EnteredHistoryID  int64
	PreviousHistoryID int64
	TaskID            string
	RetryCounts       map[int]int64
	RetryCount        int64
	ChildGeneration   int64
	NextItem          int64
	ItemCount         int64
	MaxConcurrency    int64
	MapRunARN         string
	Due               *time.Time
	Version           int64
}

type TaskKey struct {
	Scope
	ID string
}

type TaskStatus string

const (
	TaskScheduled TaskStatus = "SCHEDULED"
	TaskRunning   TaskStatus = "RUNNING"
	TaskSubmitted TaskStatus = "SUBMITTED"
	TaskSucceeded TaskStatus = "SUCCEEDED"
	// TaskFailurePending closes a payload-free callback before the runtime
	// records its history; accepting that callback does not require KMS.
	TaskFailurePending TaskStatus = "FAILURE_PENDING"
	TaskFailed         TaskStatus = "FAILED"
	TaskTimedOut       TaskStatus = "TIMED_OUT"
	TaskCancelled      TaskStatus = "CANCELLED"
)

// TaskRecord is an individual attempt. Closed attempts remain addressable by
// token, so an old callback can never complete a newer retry. Activity deadlines
// start on worker assignment, independently of the parent execution deadline.
type TaskRecord struct {
	Key               TaskKey
	Frame             FrameKey
	Attempt           int64
	Token             string
	Kind              string
	Resource          string
	Parameters        string
	RoleARN           string
	Activity          string
	Status            TaskStatus
	Scheduled         time.Time
	Started           *time.Time
	TimeoutSeconds    int64
	HeartbeatSeconds  int64
	Deadline          *time.Time
	HeartbeatDeadline *time.Time
	WorkerName        string
	// Output retains the accepted response while submitted, then the terminal
	// result. A recovered synchronous attempt must never submit that job again.
	Output         string
	Error          string
	Cause          string
	HistoryID      int64
	Version        int64
	Encrypted      *EncryptedPayload
	EncryptedInput *EncryptedPayload
}

// HistoryRecord retains the native typed event envelope. This append-only event
// document is distinct from the normalized mutable execution/frame/task state.
type HistoryRecord struct {
	Execution    ExecutionKey
	FrameID      int64
	StateID      int64
	RedriveCount int64
	Error        string
	Cause        string
	Event        api.HistoryEvent
	Encrypted    *EncryptedPayload
}

type MapRunKey struct {
	Scope
	ARN string
}

type MapRunRecord struct {
	Key                        MapRunKey
	Frame                      FrameKey
	Label                      string
	Status                     string
	Started                    time.Time
	Stopped                    *time.Time
	RedriveCount               int64
	Redriven                   *time.Time
	MaxConcurrency             int64
	ToleratedFailureCount      int64
	ToleratedFailurePercentage float64
	TotalItems                 int64
	ResultsWrittenItems        int64
	ResultsWrittenExecutions   int64
}

// MapResultFile retains the native manifest's references to successful exports
// across redrives without requiring the execution role to read its S3 output.
type MapResultFile struct {
	Generation     int64
	Status         string
	Index          int64
	Key            string
	Size           int64
	FirstExecution string
	LastExecution  string
}

type WorkKind string

const (
	WorkMachineDelete    WorkKind = "machine-delete"
	WorkExecutionTimeout WorkKind = "execution-timeout"
	WorkExecutionExpiry  WorkKind = "execution-expiry"
	WorkFrame            WorkKind = "frame"
	WorkTaskDispatch     WorkKind = "task-dispatch"
	WorkTaskTimeout      WorkKind = "task-timeout"
	WorkHeartbeatTimeout WorkKind = "heartbeat-timeout"
	WorkHistoryDelivery  WorkKind = "history-delivery"
)

// WorkRecord is a projection of authoritative deadlines, not another durable
// queue. The scheduler fences the selected resource version before transition.
type WorkRecord struct {
	Kind      WorkKind
	Due       time.Time
	Version   int64
	Machine   MachineKey
	Execution ExecutionKey
	FrameID   int64
	TaskID    string
}
