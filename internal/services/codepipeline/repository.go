// Package codepipeline owns pipeline definitions, executions and artifact lineage.
package codepipeline

import (
	"context"
	api "stackd/internal/awsapi/codepipeline"
	"time"
)

type Scope struct{ Partition, AccountID, Region string }
type Transition struct {
	Stage, Type, Reason, ChangedBy string
	Disabled                       bool
	ChangedAt                      time.Time
}
type Pipeline struct {
	Scope
	Name, Incarnation     string
	Ownership, LastUpdate string
	Version               int32
	CreatedAt, UpdatedAt  time.Time
	PollingDisabledAt     time.Time
	Tags                  map[string]string
	Transitions           []Transition
}
type Definition struct {
	Scope
	Incarnation string
	Declaration api.PipelineDeclaration
}

// Artifact retains a reserved or worker-reported S3 locator, never object bytes.
// Lambda callbacks do not prove an output exists; consumers read the real object.
// VersionID/ETag are populated only when the provider reports materialization.
// RevisionID is the original source revision, not the artifact object's VersionID.
type Artifact struct{ Name, Bucket, Key, VersionID, ETag, RevisionID, ActionExecutionID string }
type SourceRevision struct {
	ActionName, ArtifactName, RevisionID, ChangeID, Summary, URL string
	CreatedAt                                                    time.Time
}
type ActionExecution struct {
	ID, StageName, ActionName, Status                                                          string
	StageIndex, ActionIndex, Attempt                                                           int32
	StartedAt, UpdatedAt                                                                       time.Time
	UpdatedBy                                                                                  string
	ExternalExecutionID, ExternalExecutionURL, Summary, ErrorCode, ErrorMessage, ApprovalToken string
	ApprovalNotificationID                                                                     string
	InputArtifacts, OutputArtifacts                                                            []Artifact
	ResolvedConfiguration                                                                      api.ActionConfigurationMap
	OutputVariables                                                                            api.OutputVariablesMap
}
type Execution struct {
	Scope
	PipelineName, Incarnation, ID, ClientToken string
	ParentEventID                              string
	// RollbackTargetID binds retained standard history independently of new actions.
	RollbackTargetID                                              string
	RollbackStageIndex                                            int32
	Version, Attempt                                              int32
	Mode, Status, Summary, TriggerType, TriggerDetail, StopReason string
	StageIndex                                                    int32
	StageStatus                                                   string
	StageStartedAt, LastRetryAt, StageLastRetryAt                 time.Time
	StageEntered, UpdatedDefinition                               bool
	StartedAt, UpdatedAt, Due                                     time.Time
	Generation, Sequence                                          int64
	SourceOverrides                                               api.SourceRevisionOverrideList
	Variables                                                     api.ResolvedPipelineVariableList
	Revisions                                                     []SourceRevision
	Actions                                                       []ActionExecution
}

// SourcePoll retains one source action's cursor and recoverable observation lease.
// Empty RevisionID means no source revision has been observed yet.
type SourcePoll struct {
	Scope
	PipelineName, Incarnation, StageName, ActionName     string
	Bucket, ObjectKey, RevisionID, PollID, ParentEventID string
	ErrorCode, ErrorMessage                              string
	LastAttempt                                          time.Time
	PipelineVersion                                      int32
	Generation                                           int64
	Due                                                  time.Time
}

// Readers borrow the coordinated context; repository values are independent copies.
type Reader interface {
	Context() context.Context
	Pipelines(Scope) ([]Pipeline, error)
	Definition(Scope, string, int32) (Definition, bool, error)
	Executions(Scope, string) ([]Execution, error)
	PendingExecutions() ([]Execution, error)
	SourcePolls(Scope, string) ([]SourcePoll, error)
	PendingSourcePolls() ([]SourcePoll, error)
	InvocationJob(Scope, string) (InvocationJob, bool, error)
	InvocationJobs(Scope, string) ([]InvocationJob, error)
}
type Transaction interface {
	Reader
	PutPipeline(Pipeline) error
	PutDefinition(Definition) error
	PutExecution(Execution) error
	DeletePipeline(Scope, string) error
	PutSourcePoll(SourcePoll) error
	DeleteSourcePolls(Scope, string) error
	PutInvocationJob(InvocationJob) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

// ActionExecutor invokes existing service owners, never customer compute in-process.
// Execute runs outside transactions. On admission and restart it must recover the
// same provider work by ActionExecutionID; ExternalExecutionID is the retained
// provider handle on subsequent polls. Every call uses current role authority.
// Abandonment fences results but deliberately does not cancel provider work.
// Manual approval publication is at-least-once until its returned notification
// ID is retained; after that the action waits for approval without provider polls.
// Lambda dispatch uses InvocationJob identity. An accepted dispatch waits for a
// callback; a normal function return cannot complete the action. Interruption
// before InvocationAccepted is committed permits at-least-once delivery of that
// same job. Continuations create new jobs without changing action/artifact IDs.
type ActionExecutor interface {
	Execute(context.Context, ActionRequest) (ActionResult, error)
}
type ActionRequest struct {
	Scope
	PipelineName, PipelineARN, Incarnation, PipelineExecutionID, ActionExecutionID string
	StageName                                                                      string
	PipelineVersion                                                                int32
	RoleARN                                                                        string
	ParentEventID                                                                  string
	Action                                                                         api.ActionDeclaration
	ArtifactStore                                                                  api.ArtifactStore
	InputArtifacts, OutputArtifacts                                                []Artifact
	SourceRevisionOverrides                                                        []api.SourceRevisionOverride
	ExternalExecutionID                                                            string
	ApprovalToken                                                                  string
	ApprovalExpiresAt                                                              time.Time
	InvocationJob                                                                  *InvocationJob
}
type ActionResult struct {
	Status, ExternalExecutionID, ExternalExecutionURL, Summary, ErrorCode, ErrorMessage string
	ApprovalNotificationID                                                              string
	Artifacts                                                                           []Artifact
	Revision                                                                            *SourceRevision
	OutputVariables                                                                     api.OutputVariablesMap
	InvocationAccepted                                                                  bool
}

// SourceObserver reads the latest actual source version under current role
// authority outside repository transactions. Errors never consume a revision.
type SourceObserver interface {
	LatestSourceRevision(context.Context, SourcePollRequest) (string, error)
}
type SourcePollRequest struct {
	Scope
	PipelineName, PipelineARN, Incarnation, RoleARN, PollID, ParentEventID string
	PipelineVersion                                                        int32
	Action                                                                 api.ActionDeclaration
}

// StateEvents joins state-change events to the same repository transaction.
type StateEvents interface {
	PipelineStateChanged(context.Context, Pipeline, Execution) error
	StageStateChanged(context.Context, Pipeline, Execution, string, string) error
	ActionStateChanged(context.Context, Pipeline, Execution, ActionExecution, api.ActionDeclaration) error
}

// Roles validates current pipeline-role existence/trust and caller PassRole
// authority inside the shared admission transaction; it performs no provider work.
type Roles interface {
	Validate(context.Context, string, string) error
}
