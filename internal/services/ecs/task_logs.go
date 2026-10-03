package ecs

import (
	"context"

	runtime "stackd/compute/ecs"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// TaskCredentialSource resolves current credentials for the role selected by
// the ECS service: execution role for Logs, task role for customer metadata.
type TaskCredentialSource func(context.Context) (identity.Credential, *awswire.Error)

// TaskLogs initializes the destination before the container starts. The caller
// supplies execution-role credentials (never the customer task role), and the
// current task causal context to Open and every Write. Sinks refresh credentials
// for each Logs operation.
type TaskLogs interface {
	Open(context.Context, TaskKey, string, api.LogConfiguration, TaskCredentialSource) (TaskLogSink, error)
}

// TaskLogSink consumes actual engine records. Close drains accepted output;
// durable native log cursors remain the task worker's responsibility.
type TaskLogSink interface {
	Write(context.Context, runtime.LogRecord) error
	Close() error
}
