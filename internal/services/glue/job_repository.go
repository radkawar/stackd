package glue

import (
	"context"
	"strconv"
	"time"

	runtime "stackd/compute/glue"
)

type JobRuntime = runtime.Runtime

type JobExecutionInput struct {
	Script      []byte
	Environment []string
}

// JobDependencies uses current IAM authority and ordinary S3/Logs commands. None
// of these external operations run in a Glue repository transaction.
type JobDependencies interface {
	Credentials(context.Context, JobRunRecord) (runtime.Credentials, error)
	Prepare(context.Context, JobRecord, JobRunRecord) (JobExecutionInput, error)
	Publish(context.Context, JobRunRecord, string) error
	PublishMetrics(context.Context, JobRunRecord) error
}

type JobRecord struct {
	Key                                                                    ResourceKey
	Description, Role, Command, ScriptLocation, PythonVersion, GlueVersion string
	WorkerType, ExecutionClass, SecurityConfiguration                      string
	MaxConcurrentRuns, MaxRetries, Timeout, NumberOfWorkers                int32
	MaxCapacity                                                            float64
	DefaultArguments, NonOverridableArguments, Tags                        map[string]string
	CreatedAt, UpdatedAt                                                   time.Time
}

type JobRunRecord struct {
	Key                                                                  ResourceKey
	ID, State, Role, Command, ScriptLocation, PythonVersion, GlueVersion string
	WorkerType, ExecutionClass, SecurityConfiguration                    string
	PreviousRunID, TriggerName, WorkflowName, WorkflowRunID              string
	S3EncryptionMode, S3KMSKeyARN, LogsKMSKeyARN                         string
	MaxRetries                                                           int32
	ExecutionSeconds                                                     int32
	Timeout, NumberOfWorkers, Attempt                                    int32
	MaxCapacity                                                          float64
	Arguments                                                            map[string]string
	RunArguments                                                         map[string]string
	Attempts                                                             []JobAttemptRecord
	SparkMetrics                                                         runtime.SparkMetrics
	StartedAt, UpdatedAt, CompletedAt, NextAttempt                       time.Time
	Version                                                              uint64
	LaunchAttempted, CleanupPending, Published                           bool
	RetryPending, MetricsPublished                                       bool
	Error, Output, ErrorOutput, LogError                                 string
}

type JobAttemptRecord struct {
	Attempt                           int32
	State, Error, Output, ErrorOutput string
	StartedAt, CompletedAt            time.Time
}

func (r JobRunRecord) ExecutionKey() string {
	return r.Key.ARN("job") + "/" + r.ID + "/attempt-" + strconv.Itoa(int(r.Attempt))
}
func (r JobRunRecord) Active() bool {
	return r.State == "STARTING" || r.State == "RUNNING" || r.State == "STOPPING"
}

type JobsReader interface {
	GetJob(ResourceKey) (JobRecord, error)
	ListJobs(Scope) ([]JobRecord, error)
	GetJobRun(ResourceKey, string) (JobRunRecord, error)
	ListJobRuns(ResourceKey) ([]JobRunRecord, error)
	PendingJobRuns() ([]JobRunRecord, error)
}
type JobsWriter interface {
	PutJob(JobRecord) error
	DeleteJob(ResourceKey) error
	PutJobRun(JobRunRecord) error
}
