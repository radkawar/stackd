package glue

import (
	api "stackd/internal/awsapi/glue"
	"time"
)

type WorkflowRecord struct {
	Key      ResourceKey
	Workflow api.Workflow
	Tags     map[string]string
}
type TriggerRecord struct {
	Key      ResourceKey
	Trigger  api.Trigger
	Tags     map[string]string
	NextFire *time.Time
}
type SecurityConfigurationRecord struct {
	Key           ResourceKey
	Configuration api.SecurityConfiguration
}

// WorkflowNodeRun is the retained execution graph. A trigger node owns its
// predicate; a job/crawler node owns its action and the actual child run ID.
type WorkflowNodeRun struct {
	ID, Kind, Name, TriggerName, RunID, State, Error               string
	TriggerType, TriggerState, TriggerDescription, TriggerSchedule string
	Action                                                         api.Action
	Conditions                                                     api.ConditionList
	Logical                                                        string
	Activated                                                      bool
}
type WorkflowRunRecord struct {
	Key                                           ResourceKey
	ID, PreviousRunID, RootTrigger, Status, Error string
	Started                                       time.Time
	Completed, NextPoll                           *time.Time
	Properties                                    api.WorkflowRunProperties
	Nodes                                         []WorkflowNodeRun
}
type WorkflowsReader interface {
	Workflow(ResourceKey) (WorkflowRecord, error)
	Workflows(Scope) ([]WorkflowRecord, error)
	Trigger(ResourceKey) (TriggerRecord, error)
	Triggers(Scope) ([]TriggerRecord, error)
	SecurityConfiguration(ResourceKey) (SecurityConfigurationRecord, error)
	SecurityConfigurations(Scope) ([]SecurityConfigurationRecord, error)
	WorkflowRun(ResourceKey, string) (WorkflowRunRecord, error)
	WorkflowRuns(ResourceKey) ([]WorkflowRunRecord, error)
	NextWorkflowRun() (WorkflowRunRecord, bool, error)
	NextTrigger() (TriggerRecord, bool, error)
}
type WorkflowsWriter interface {
	PutWorkflow(WorkflowRecord) error
	DeleteWorkflow(ResourceKey) error
	PutTrigger(TriggerRecord) error
	DeleteTrigger(ResourceKey) error
	PutSecurityConfiguration(SecurityConfigurationRecord) error
	DeleteSecurityConfiguration(ResourceKey) error
	PutWorkflowRun(WorkflowRunRecord) error
}
