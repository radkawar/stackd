package stepfunctions

import (
	"context"
	"errors"

	metricsapi "stackd/internal/awsapi/cloudwatch"
)

// TaskRunner invokes actual destination commands after the workflow transaction
// commits. An ASL task failure is an outcome; a Go error means the effect could
// not be resolved. Completion is fenced against the retained attempt version.
type TaskRunner interface {
	Run(context.Context, TaskRecord, RevisionRecord, func(TaskOutcome) error) (TaskOutcome, error)
}

// ErrTaskInterrupted distinguishes process shutdown from workflow cancellation.
// Accepted external jobs remain running so a retained attempt can resume them.
var ErrTaskInterrupted = errors.New("step functions task interrupted by service shutdown")

type TaskOutcome struct {
	Output    string
	Error     string
	Cause     string
	Submitted bool
}

// ExecutionEventPublisher admits native status events in the source transaction.
type ExecutionEventPublisher interface {
	PublishExecutionState(context.Context, ExecutionRecord) error
}

// HistoryPublisher owns configured CloudWatch Logs delivery, not execution state.
type HistoryPublisher interface {
	ConfigureLogging(context.Context, RevisionRecord) error
	PublishHistory(context.Context, HistoryRecord, ExecutionRecord, RevisionRecord) error
}

type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}
