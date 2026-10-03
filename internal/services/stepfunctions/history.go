package stepfunctions

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	api "stackd/internal/awsapi/stepfunctions"
)

const executionHistoryLimit int64 = 25000

const historyLimitErrorName = "States.Runtime"
const historyLimitCause = "The execution reached the maximum number of history events (25000)."

var errHistoryLimit = errors.New("execution history limit exceeded")

func historyLimitReached(execution *ExecutionRecord) bool {
	return execution.Type == "STANDARD" && execution.NextHistoryID >= executionHistoryLimit-1
}

// transitionExecution checks machine deletion before the next execution event
// and isolates partial branch/task admission from a history-limit failure.
// Both terminate through the ordinary cancellation and observation owner.
func (s *Service) transitionExecution(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, at time.Time, effects *transitionEffects, transition func(Transaction) error) (bool, error) {
	machine, err := tx.Machine(execution.Machine)
	if err != nil {
		return false, err
	}
	if machine.Status == "DELETING" {
		return true, s.endExecution(tx, execution, revision, "FAILED", "", "States.Runtime", "State machine "+machine.Key.Name+" has been deleted", at, effects)
	}
	if execution.Type != "STANDARD" {
		return false, transition(tx)
	}
	before, priorEffects := *execution, *effects
	var admitted []HistoryRecord
	err = s.repository.Attempt(tx.Context(), func(command Transaction) error {
		if encrypted, ok := tx.(*workflowTransaction); ok {
			command = encrypted.rebind(command)
		}
		err := transition(command)
		if !errors.Is(err, errHistoryLimit) {
			return err
		}
		admitted = make([]HistoryRecord, 0, execution.NextHistoryID-before.NextHistoryID)
		for id := before.NextHistoryID + 1; id <= execution.NextHistoryID; id++ {
			event, readErr := command.HistoryEvent(execution.Key, id)
			if readErr != nil {
				return readErr
			}
			admitted = append(admitted, event)
		}
		return err
	})
	if !errors.Is(err, errHistoryLimit) {
		return false, err
	}
	*execution, *effects = before, priorEffects
	for _, event := range admitted {
		if err := tx.AppendHistory(event); err != nil {
			return false, err
		}
		execution.NextHistoryID = int64(*event.Event.Id)
	}
	return true, s.endExecution(tx, execution, revision, "FAILED", "", historyLimitErrorName, historyLimitCause, at, effects)
}

func (s *Service) appendHistory(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, at time.Time, record HistoryRecord) (int64, error) {
	event := record.Event
	if execution.Type == "STANDARD" {
		limitFailure := value(event.Type) == "ExecutionFailed" && event.ExecutionFailedEventDetails != nil && value(event.ExecutionFailedEventDetails.Error) == historyLimitErrorName && value(event.ExecutionFailedEventDetails.Cause) == historyLimitCause
		if execution.NextHistoryID >= executionHistoryLimit || historyLimitReached(execution) && value(event.Type) != "ExecutionSucceeded" && !limitFailure {
			return 0, errHistoryLimit
		}
	}
	execution.NextHistoryID++
	event.Id = new(api.EventId(execution.NextHistoryID))
	event.Timestamp = new(api.Timestamp(at.UTC()))
	if event.PreviousEventId == nil {
		event.PreviousEventId = new(api.EventId(0))
	}
	record.Execution, record.Event, record.RedriveCount = execution.Key, event, execution.RedriveCount
	if event.StateEnteredEventDetails != nil {
		record.StateID = execution.NextHistoryID
	}
	if err := tx.AppendHistory(record); err != nil {
		return 0, err
	}
	return execution.NextHistoryID, nil
}

func historyEvent(kind string, previous int64) api.HistoryEvent {
	return api.HistoryEvent{Type: new(api.HistoryEventType(kind)), PreviousEventId: new(api.EventId(previous))}
}

// frameHistory retains immutable source identity before a reusable frame moves
// to its next state. It is internal metadata, not part of the AWS event document.
func frameHistory(frame *FrameRecord, event api.HistoryEvent) HistoryRecord {
	return HistoryRecord{FrameID: frame.Key.ID, StateID: frame.EnteredHistoryID, Event: event}
}

func (s *Service) stateEntered(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, kind string, at time.Time) error {
	event := historyEvent(kind+"StateEntered", frame.PreviousHistoryID)
	event.StateEnteredEventDetails = &api.StateEnteredEventDetails{
		Name: new(api.Name(frame.StateName)), Input: new(api.SensitiveData(frame.Input)),
		InputDetails: &api.HistoryEventExecutionDataDetails{Truncated: new(api.Truncated(false))},
	}
	id, err := s.appendHistory(tx, execution, revision, at, frameHistory(frame, event))
	if err != nil {
		return err
	}
	frame.Entered, frame.EnteredHistoryID, frame.PreviousHistoryID = at, id, id
	return nil
}

func (s *Service) stateExited(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, kind, output string, assigned api.AssignedVariables, at time.Time) error {
	event := historyEvent(kind+"StateExited", frame.PreviousHistoryID)
	event.StateExitedEventDetails = &api.StateExitedEventDetails{
		Name: new(api.Name(frame.StateName)), Output: new(api.SensitiveData(output)),
		OutputDetails:     &api.HistoryEventExecutionDataDetails{Truncated: new(api.Truncated(false))},
		AssignedVariables: assigned,
	}
	if assigned != nil {
		event.StateExitedEventDetails.AssignedVariablesDetails = &api.AssignedVariablesDetails{Truncated: new(api.Truncated(false))}
	}
	id, err := s.appendHistory(tx, execution, revision, at, frameHistory(frame, event))
	if err != nil {
		return err
	}
	frame.PreviousHistoryID = id
	return nil
}

// inspectAssignments records precisely this state's bindings, including writes
// that retain a previous value; diffing the resulting scope would lose those.
func inspectAssignments(target *api.AssignedVariables) stateInspection {
	return func(stage string, data any) error {
		if stage != "variables" {
			return nil
		}
		bindings := data.(map[string]json.RawMessage)
		*target = make(api.AssignedVariables, len(bindings))
		for name, encoded := range bindings {
			(*target)[api.VariableName(name)] = api.VariableValue(encoded)
		}
		return nil
	}
}

// requestContext starts a trusted service continuation without retaining the
// caller's credentials. Target adapters assume the configured execution role.
func requestContext(ctx context.Context, execution ExecutionRecord) context.Context {
	return continuationContext(ctx, execution.Key.Scope, execution.ParentEventID, execution.TraceHeader)
}
