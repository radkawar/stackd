package stepfunctions

import (
	"strings"
	"time"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/services/stepfunctions/asl"
)

func (s *Service) redriveExecution(tx Transaction, in *api.RedriveExecutionInput) (*api.RedriveExecutionOutput, error) {
	raw := value(in.ExecutionArn)
	if parts := strings.SplitN(raw, ":", 7); len(parts) == 7 && parts[5] == "execution" && strings.Contains(parts[6], "/") {
		return nil, invalid("Labeled Execution ARNs are not supported for this API")
	}
	execution, err := s.publicExecutionFor(tx, raw, "RedriveExecution")
	if err != nil {
		return nil, err
	}
	token := value(in.ClientToken)
	if in.ClientToken != nil {
		if len(token) == 0 || len(token) > 64 {
			return nil, invalid("clientToken must contain between 1 and 64 printable ASCII characters.")
		}
		for _, c := range token {
			if c < '!' || c > '~' {
				return nil, invalid("clientToken must contain between 1 and 64 printable ASCII characters.")
			}
		}
	}
	now := s.clock.Now().UTC()
	requests, err := tx.RedriveRequests(execution.Key)
	if err != nil {
		return nil, err
	}
	retained := requests[:0]
	for _, request := range requests {
		if !now.Before(request.Date.Add(15 * time.Minute)) {
			continue
		}
		if token != "" && request.Token == token {
			return &api.RedriveExecutionOutput{RedriveDate: controlTimestamp(request.Date)}, nil
		}
		retained = append(retained, request)
	}
	if status, reason := executionRedrive(execution, now); status != "REDRIVABLE" {
		return nil, failure("ExecutionNotRedrivable", reason, 400)
	}
	revision, err := tx.Revision(RevisionKey{Scope: execution.Key.Scope, ID: execution.RevisionID})
	if err != nil {
		return nil, err
	}
	working := s.workflowTransaction(tx, revision, revision.RoleARN)
	execution, err = working.reader.execution(execution)
	if err != nil {
		return nil, err
	}
	revision, err = working.Revision(revision.Key)
	if err != nil {
		return nil, err
	}
	tx = working
	if err := requireOpenExecutionCapacity(tx, execution.Key.Scope); err != nil {
		return nil, err
	}
	if err := s.resumeExecution(tx, &execution, revision, now); err != nil {
		return nil, err
	}
	if token != "" {
		if len(retained) >= 10 {
			retained = retained[len(retained)-9:]
		}
		retained = append(retained, RedriveRequest{Token: token, Count: execution.RedriveCount, Date: now})
	}
	if err := tx.PutRedriveRequests(execution.Key, retained); err != nil {
		return nil, err
	}
	return &api.RedriveExecutionOutput{RedriveDate: controlTimestamp(now)}, nil
}

// resumeExecution resumes the retained state, not a new admission of the current
// machine definition. Closed task tokens remain closed and successful branches
// retain their outputs, variables and history.
func (s *Service) resumeExecution(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, at time.Time) error {
	definition, err := s.compiled(revision)
	if err != nil {
		return err
	}
	execution.Status, execution.Output, execution.Error, execution.Cause = "RUNNING", "", "", ""
	execution.Stopped, execution.Expires = nil, nil
	execution.RedriveCount++
	execution.Redriven = new(at)
	execution.Deadline = at.Add(executionTimeout(execution.Type, definition.TimeoutSeconds))
	event := historyEvent("ExecutionRedriven", execution.NextHistoryID)
	event.ExecutionRedrivenEventDetails = &api.ExecutionRedrivenEventDetails{RedriveCount: new(api.RedriveCount(execution.RedriveCount))}
	if _, err := s.appendHistory(tx, execution, revision, at, HistoryRecord{Event: event}); err != nil {
		return err
	}
	root, err := tx.Frame(FrameKey{Execution: execution.Key, ID: 1})
	if err != nil {
		return err
	}
	// Resume through the scheduler so compound-state history and failures use
	// the same transactional history-limit boundary as every other transition.
	root.Phase, root.Due = FrameRedrive, new(at)
	root.Version++
	if err := tx.PutFrame(root); err != nil {
		return err
	}
	if s.events != nil {
		if err := s.events.PublishExecutionState(tx.Context(), *execution); err != nil {
			return err
		}
	}
	if err := s.executionStartedMetrics(tx.Context(), *execution); err != nil {
		return err
	}
	execution.Version++
	return tx.PutExecution(*execution)
}

func (s *Service) redriveFrame(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, frames []FrameRecord, at time.Time) error {
	definition, err := s.compiled(revision)
	if err != nil {
		return err
	}
	scope, err := definitionScope(definition, frame.ScopePath)
	if err != nil {
		return err
	}
	state := scope.States[frame.StateName]
	previous := *frame
	frame.Phase, frame.Due, frame.TaskID = FrameReady, new(at), ""
	frame.Error, frame.Cause, frame.Output = "", "", ""
	frame.RetryCount, frame.RetryCounts = 0, nil
	frame.PreviousHistoryID = frame.EnteredHistoryID
	resumeChildren := previous.Error != "States.DataLimitExceeded" && previous.Error != "States.Runtime"
	if previous.Error == "States.Runtime" && frame.MapRunARN != "" {
		run, err := tx.MapRun(MapRunKey{Scope: execution.Key.Scope, ARN: frame.MapRunARN})
		if err != nil {
			return err
		}
		// A role-denied Map Run resumes its retained items. An interpolation
		// failure after a successful run instead starts a new run.
		resumeChildren = run.Status == "FAILED"
	}
	if (state.Type == asl.Map || state.Type == asl.Parallel) && resumeChildren {
		if frame.MapRunARN != "" {
			if err := s.redriveMapRun(tx, execution, revision, frame, previous.PreviousHistoryID, at); err != nil {
				return err
			}
		} else {
			for _, child := range frames {
				if !currentChild(previous, child) {
					continue
				}
				frame.Phase = FrameJoining
				if child.Phase != FrameComplete {
					if err := s.redriveFrame(tx, execution, revision, &child, frames, at); err != nil {
						return err
					}
				}
			}
		}
	}
	if frame.Phase == FrameReady {
		frame.Arguments = ""
		frame.NextItem, frame.ItemCount, frame.MaxConcurrency, frame.MapRunARN = 0, 0, 0, ""
	}
	frame.Version++
	return tx.PutFrame(*frame)
}

func executionTimeout(kind string, seconds int64) time.Duration {
	limit := 365 * 24 * time.Hour
	if kind == "EXPRESS" {
		limit = 5 * time.Minute
	}
	if seconds > 0 {
		return min(limit, time.Duration(seconds)*time.Second)
	}
	return limit
}
