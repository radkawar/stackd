package stepfunctions

import (
	"context"
	"time"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awswire"
	"stackd/internal/services/stepfunctions/asl"
)

// AuthorizeMapExecutions checks the actual execution-role context supplied by
// the external task adapter. It never starts a public parent workflow recursively.
func (s *Service) AuthorizeMapExecutions(ctx context.Context, arn string) *awswire.Error {
	err := s.repository.View(ctx, func(r Reader) error {
		key, err := mapRunKeyFor(r, arn)
		if err != nil {
			return err
		}
		run, err := r.MapRun(key)
		if err != nil {
			return err
		}
		if run.RedriveCount > 1000 {
			return invalid("The Map Run exceeded the maximum of 1000 redrives.")
		}
		parent, machine, err := s.retainedExecution(r, run.Frame.Execution)
		if err != nil {
			return err
		}
		children, err := r.Executions(ExecutionSelection{Scope: key.Scope, MapRunARN: arn})
		if err != nil {
			return err
		}
		start := false
		for _, child := range children {
			if child.Status == "PENDING" {
				start = true
			} else if run.RedriveCount > 0 && mapChildRedrivable(child, s.clock.Now()) {
				if child.Type == "EXPRESS" {
					start = true
				} else if denied := s.authorize(r, "RedriveExecution", child.Key.ARN, machine.Tags, nil); denied != nil {
					return denied
				}
			}
		}
		if start {
			if denied := s.authorize(r, "StartExecution", parent.Machine.ARN(), machine.Tags, nil); denied != nil {
				return denied
			}
		}
		return nil
	})
	return wireError(err)
}

func mapChildRedrivable(child ExecutionRecord, at time.Time) bool {
	if child.Status != "FAILED" && child.Status != "ABORTED" && child.Status != "TIMED_OUT" {
		return false
	}
	if child.Type == "EXPRESS" {
		return true
	}
	status, _ := executionRedrive(child, at)
	return status == "REDRIVABLE_BY_MAP_RUN"
}

func (s *Service) redriveMapRun(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, previous int64, at time.Time) error {
	run, err := tx.MapRun(MapRunKey{Scope: execution.Key.Scope, ARN: frame.MapRunARN})
	if err != nil {
		return err
	}
	run.Status, run.Stopped, run.Redriven = "RUNNING", nil, new(at)
	run.RedriveCount++
	if err := tx.PutMapRun(run); err != nil {
		return err
	}
	// Each generation links back to the original MapStateStarted event.
	// Follow the current run's retained causal chain, not the execution's
	// latest event (which may belong to a sibling branch).
	for {
		record, err := tx.HistoryEvent(execution.Key, previous)
		if err != nil {
			return err
		}
		previous = int64(*record.Event.PreviousEventId)
		if record.Event.MapRunStartedEventDetails != nil || record.Event.MapRunRedrivenEventDetails != nil {
			break
		}
	}
	event := historyEvent("MapRunRedriven", previous)
	event.MapRunRedrivenEventDetails = &api.MapRunRedrivenEventDetails{MapRunArn: new(api.LongArn(run.Key.ARN)), RedriveCount: new(api.RedriveCount(run.RedriveCount))}
	frame.PreviousHistoryID, err = s.appendHistory(tx, execution, revision, at, frameHistory(frame, event))
	if err != nil {
		return err
	}
	return s.scheduleMapEffect(tx, execution, revision, frame, "MAP_REDRIVE", run.Key.ARN, "{}", at)
}

func (s *Service) resumeMapExecutions(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, task TaskRecord, at time.Time, effects *transitionEffects) error {
	run, err := tx.MapRun(MapRunKey{Scope: execution.Key.Scope, ARN: frame.MapRunARN})
	if err != nil {
		return err
	}
	children, err := tx.Executions(ExecutionSelection{Scope: run.Key.Scope, MapRunARN: run.Key.ARN})
	if err != nil {
		return err
	}
	if task.Status != TaskSucceeded {
		return s.failMapResults(tx, execution, revision, frame, state, env, run, "States.Runtime", task.Cause, at, effects)
	}
	if task.Kind == "MAP_REDRIVE" && len(children) == 0 && state.Map.ItemReader != nil {
		// A failed or interrupted read has no admitted child inputs to retain.
		// Re-read S3 on redrive, then authorize the newly discovered children.
		arguments, err := stateArguments(tx.Context(), state, env)
		if err != nil {
			return err
		}
		return s.startMapReader(tx, execution, revision, frame, state, mapInputEnvironment(state, env, arguments), at)
	}
	if run.RedriveCount > 0 {
		for _, child := range children {
			if !mapChildRedrivable(child, at) {
				continue
			}
			child.Status = "PENDING_REDRIVE"
			child.Version++
			if err := tx.PutExecution(child); err != nil {
				return err
			}
		}
	}
	frame.Phase, frame.TaskID, frame.Due = FrameJoining, "", new(at)
	return nil
}
