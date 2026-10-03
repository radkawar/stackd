package ecs

import (
	api "stackd/internal/awsapi/ecs"
	"time"
)

type TaskKey struct {
	ClusterKey
	ID string
}

func (k TaskKey) ARN() string {
	return "arn:" + k.Partition + ":ecs:" + k.Region + ":" + k.AccountID + ":task/" + k.Name + "/" + k.ID
}

// TaskRecord retains generated task state and the immutable admitted definition.
// Current tags live exclusively in TagRecord; Data.Tags is always nil in storage.
// Runtime maps retain metadata capabilities, log continuation and dependency waits.
type TaskRecord struct {
	Key                  TaskKey
	Data                 api.Task
	Definition           api.TaskDefinition
	NetworkConfiguration api.AwsVpcConfiguration
	AcceptedEventID      string
	// Service ownership is assigned only by the scheduler, never inferred from
	// caller-controlled task Group or StartedBy fields.
	ServiceName           string
	ServiceDeploymentID   string
	CredentialToken       string
	MetadataTokens        map[string]string
	LogCursors            map[string]time.Time
	DependencyWaitStarted map[string]time.Time
}

type TaskQuery struct {
	ClusterKey
	AfterID       string
	Limit         int
	DesiredStatus string
	Family        string
	StartedBy     string
	LaunchType    string
	ServiceName   string
	ActiveOnly    bool
}

type TaskRunKey struct {
	ClusterKey
	ClientToken string
}

// TaskRunRecord retains the exact admitted request independently of task updates.
// Expiration, when applicable, belongs to the service rather than the repository.
type TaskRunRecord struct {
	Key     TaskRunKey
	Input   api.RunTaskInput
	TaskIDs []string
	Created time.Time
}
