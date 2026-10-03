package ecs

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/ecs"
)

// TaskEvent is the native event for one task transition, not an API response.
type TaskEvent struct {
	ID     string
	Key    TaskKey
	At     time.Time
	Detail json.RawMessage
}

// TaskEventPublisher admits the event and matching target work in the caller's
// transaction. The context carries that transaction and the originating API ID.
type TaskEventPublisher interface {
	PublishTaskEvent(context.Context, TaskEvent) error
}

// The captured task_dependency_transitions events use millisecond UTC detail
// timestamps, independently of the second-precision EventBridge envelope.
const taskEventTimeLayout = "2006-01-02T15:04:05.000Z"

// Embed the generated task shape rather than duplicate its public fields. Only
// native-event timestamps differ in representation; API-only fields are cleared
// on a detached projection below, never on the stored/API task.
type taskEventDetail struct {
	api.Task
	ConnectivityAt     string `json:"connectivityAt,omitempty"`
	CreatedAt          string `json:"createdAt,omitempty"`
	ExecutionStoppedAt string `json:"executionStoppedAt,omitempty"`
	PullStartedAt      string `json:"pullStartedAt,omitempty"`
	PullStoppedAt      string `json:"pullStoppedAt,omitempty"`
	StartedAt          string `json:"startedAt,omitempty"`
	StoppedAt          string `json:"stoppedAt,omitempty"`
	StoppingAt         string `json:"stoppingAt,omitempty"`
	UpdatedAt          string `json:"updatedAt"`
}

func taskEventTime(at *time.Time) string {
	if at == nil {
		return ""
	}
	return at.UTC().Format(taskEventTimeLayout)
}

func taskEventProjection(task api.Task) api.Task {
	task.HealthStatus = nil
	task.PlatformFamily = nil
	task.FargateEphemeralStorage = nil
	task.Tags = nil
	task.Attachments = slices.Clone(task.Attachments)
	for i := range task.Attachments {
		if value(task.Attachments[i].Type) == "ElasticNetworkInterface" {
			task.Attachments[i].Type = new(api.String("eni"))
		}
	}
	task.Containers = slices.Clone(task.Containers)
	for i := range task.Containers {
		container := &task.Containers[i]
		container.HealthStatus = nil
		container.ManagedAgents = nil
		if len(container.NetworkBindings) == 0 {
			container.NetworkBindings = nil
		}
	}
	if task.Overrides != nil {
		overrides := *task.Overrides
		if len(overrides.InferenceAcceleratorOverrides) == 0 {
			overrides.InferenceAcceleratorOverrides = nil
		}
		// Native state events retain environment overrides; CloudTrail applies
		// its separate redaction projection in audit.go.
		task.Overrides = &overrides
	}
	return task
}

func taskEvent(record TaskRecord, at time.Time) (TaskEvent, error) {
	task := taskEventProjection(record.Data)
	detail, err := json.Marshal(taskEventDetail{
		Task:           task,
		ConnectivityAt: taskEventTime(task.ConnectivityAt), CreatedAt: taskEventTime(task.CreatedAt),
		ExecutionStoppedAt: taskEventTime(task.ExecutionStoppedAt),
		PullStartedAt:      taskEventTime(task.PullStartedAt), PullStoppedAt: taskEventTime(task.PullStoppedAt),
		StartedAt: taskEventTime(task.StartedAt), StoppedAt: taskEventTime(task.StoppedAt),
		StoppingAt: taskEventTime(task.StoppingAt), UpdatedAt: at.UTC().Format(taskEventTimeLayout),
	})
	if err != nil {
		return TaskEvent{}, err
	}
	return TaskEvent{ID: uuid.NewString(), Key: record.Key, At: at, Detail: detail}, nil
}
