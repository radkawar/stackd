package ecs

import (
	"context"

	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// TaskRoles separates the deploying caller's PassRole and admission trust check
// from credentials issued to actual task and execution-role consumers.
type TaskRoles interface {
	Validate(context.Context, string, string) error
	Assume(context.Context, string, string) (identity.Credential, *awswire.Error)
}

// TaskParameters retrieves SSM and Secrets Manager values with the execution role.
// The map is keyed by original references and is never persisted in task state.
type TaskParameters interface {
	Read(context.Context, TaskKey, []string, TaskCredentialSource) (map[string]string, error)
}

// TaskEnvironmentFiles reads S3 objects only when a native container is created.
type TaskEnvironmentFiles interface {
	Read(context.Context, TaskKey, string, TaskCredentialSource) ([]byte, error)
}
