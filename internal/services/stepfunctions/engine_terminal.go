package stepfunctions

import (
	"time"

	api "stackd/internal/awsapi/stepfunctions"
)

// endExecution is the sole terminal transition. Its caller persists the updated
// execution together with frames, history, and source observations.
func (s *Service) endExecution(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, status, output, name, cause string, at time.Time, effects *transitionEffects) error {
	if execution.Status != "RUNNING" {
		return nil
	}
	if status != "SUCCEEDED" && historyLimitReached(execution) {
		status, output, name, cause = "FAILED", "", historyLimitErrorName, historyLimitCause
	}
	if status != "SUCCEEDED" {
		if err := s.abortDescendants(tx, execution, revision, nil, at, effects); err != nil {
			return err
		}
	}
	execution.Status, execution.Output, execution.Error, execution.Cause = status, output, name, cause
	execution.Stopped = new(at)
	if execution.MapRunARN == "" {
		execution.Expires = new(at.Add(90 * 24 * time.Hour))
	}
	previous := execution.NextHistoryID
	if status == "ABORTED" || status == "TIMED_OUT" {
		previous = 0
	}
	var errorName *api.SensitiveError
	var errorCause *api.SensitiveCause
	if name != "" {
		errorName = new(api.SensitiveError(name))
	}
	if cause != "" {
		errorCause = new(api.SensitiveCause(cause))
	}
	var event api.HistoryEvent
	switch status {
	case "SUCCEEDED":
		event = historyEvent("ExecutionSucceeded", previous)
		event.ExecutionSucceededEventDetails = &api.ExecutionSucceededEventDetails{
			Output:        new(api.SensitiveData(output)),
			OutputDetails: &api.HistoryEventExecutionDataDetails{Truncated: new(api.Truncated(false))},
		}
	case "FAILED":
		event = historyEvent("ExecutionFailed", previous)
		event.ExecutionFailedEventDetails = &api.ExecutionFailedEventDetails{Error: errorName, Cause: errorCause}
	case "ABORTED":
		event = historyEvent("ExecutionAborted", previous)
		event.ExecutionAbortedEventDetails = &api.ExecutionAbortedEventDetails{Error: errorName, Cause: errorCause}
	case "TIMED_OUT":
		event = historyEvent("ExecutionTimedOut", previous)
		event.ExecutionTimedOutEventDetails = &api.ExecutionTimedOutEventDetails{Error: new(api.SensitiveError("States.Timeout")), Cause: errorCause}
	}
	if _, err := s.appendHistory(tx, execution, revision, at, HistoryRecord{Event: event}); err != nil {
		return err
	}
	if err := s.executionEndedMetrics(tx.Context(), *execution); err != nil {
		return err
	}
	if s.events != nil {
		if err := s.events.PublishExecutionState(tx.Context(), *execution); err != nil {
			return err
		}
	}
	if execution.MapRunARN != "" {
		return s.distributedChildFinished(tx, execution, at)
	}
	return nil
}
