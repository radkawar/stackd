package stepfunctions

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/services/stepfunctions/asl"
)

func (s *Service) runFrame(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame FrameRecord, at time.Time, effects *transitionEffects) error {
	if frame.Phase == FrameRedrive {
		frames, err := tx.Frames(execution.Key)
		if err != nil {
			return err
		}
		return s.redriveFrame(tx, execution, revision, &frame, frames, at)
	}
	root, err := s.compiled(revision)
	if err != nil {
		return err
	}
	definition, err := definitionScope(root, frame.ScopePath)
	if err != nil {
		return err
	}
	state := definition.States[frame.StateName]
	if state == nil {
		return fmt.Errorf("retained workflow state %q does not exist", frame.StateName)
	}
	frame.Due = nil
	if frame.EnteredHistoryID == 0 {
		if err := s.stateEntered(tx, execution, revision, &frame, string(state.Type), at); err != nil {
			return err
		}
	}
	if err := observeExecutionMemory(tx, execution, revision, frame); err != nil {
		return err
	}
	env, err := evaluationEnvironment(*execution, revision, frame, state, at)
	if err != nil {
		return err
	}
	var evaluationError error
	switch frame.Phase {
	case FrameWaiting:
		var result any
		if err := json.Unmarshal([]byte(frame.Arguments), &result); err != nil {
			return err
		}
		evaluationError = s.finishState(tx, execution, revision, &frame, state, env, result, state.Next, state.Assign, state.Output, at, effects)
	case FrameTask:
		evaluationError = s.resumeTask(tx, execution, revision, &frame, state, env, at, effects)
	case FrameJoining:
		evaluationError = s.joinChildren(tx, execution, revision, &frame, state, env, at, effects)
	case FrameReady:
		evaluationError = s.enterState(tx, execution, revision, &frame, state, env, at, effects)
	default:
		return nil
	}
	if evaluationError != nil {
		var failure *asl.EvaluationError
		if !errors.As(evaluationError, &failure) {
			return evaluationError
		}
		if err := s.recordEvaluationFailure(tx, execution, revision, &frame, failure, at); err != nil {
			return err
		}
		if err := s.failState(tx, execution, revision, &frame, state, env, failure.Name, failure.Cause, at, effects); err != nil {
			return err
		}
	}
	frame.Version++
	return tx.PutFrame(frame)
}

// enterState routes owned behavior; all completion and failure paths converge on
// finishState/failState rather than inventing a second machine for each kind.
func (s *Service) enterState(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, at time.Time, effects *transitionEffects) error {
	if state.Type == asl.Task {
		return s.scheduleTask(tx, execution, revision, frame, state, env, at)
	}
	evaluated, err := evaluateState(tx.Context(), state, env, at, nil)
	if err != nil {
		return err
	}
	if evaluated.Failure != nil {
		return s.failState(tx, execution, revision, frame, state, env, evaluated.Failure.Name, evaluated.Failure.Cause, at, effects)
	}
	switch state.Type {
	case asl.Wait:
		frame.Arguments, err = encodeExecutionData(evaluated.Arguments)
		if err != nil {
			return err
		}
		frame.Phase, frame.Due = FrameWaiting, evaluated.Due
		return nil
	case asl.Parallel, asl.Map:
		return s.startChildren(tx, execution, revision, frame, state, env, evaluated.Arguments, at, effects)
	default:
		return s.finishState(tx, execution, revision, frame, state, env, evaluated.Result, evaluated.Next, evaluated.Assign, evaluated.Output, at, effects)
	}
}

func (s *Service) finishState(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, result any, next string, assign, output *asl.Template, at time.Time, effects *transitionEffects) error {
	env.HasResult = state.Type == asl.Task || state.Type == asl.Map || state.Type == asl.Parallel
	if env.HasResult {
		env.Result = result
	}
	var assigned api.AssignedVariables
	encoded, variables, err := stateOutput(tx.Context(), state, env, result, assign, output, inspectAssignments(&assigned))
	if err != nil {
		return err
	}
	if err := applyFrameVariables(tx, frame, variables); err != nil {
		return err
	}
	frame.Output = encoded
	if err := observeExecutionMemory(tx, execution, revision, *frame); err != nil {
		return err
	}
	if err := s.stateExited(tx, execution, revision, frame, string(state.Type), encoded, assigned, at); err != nil {
		return err
	}
	if state.End || state.Type == asl.Succeed {
		frame.Phase, frame.Output = FrameComplete, encoded
		if frame.ParentID == 0 {
			return s.endExecution(tx, execution, revision, "SUCCEEDED", encoded, "", "", at, effects)
		}
		return s.childFinished(tx, execution, revision, *frame, at, effects)
	}
	frame.StateName, frame.Input = next, encoded
	frame.Output = ""
	frame.Phase, frame.Due = FrameReady, new(at)
	frame.EnteredHistoryID, frame.RetryCount = 0, 0
	frame.RetryCounts, frame.TaskID, frame.Arguments = nil, "", ""
	frame.NextItem, frame.ItemCount, frame.MaxConcurrency, frame.MapRunARN = 0, 0, 0, ""
	return nil
}

func (s *Service) recordEvaluationFailure(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, failure *asl.EvaluationError, at time.Time) error {
	if failure.Location == "" {
		return nil
	}
	event := historyEvent("EvaluationFailed", frame.PreviousHistoryID)
	event.EvaluationFailedEventDetails = &api.EvaluationFailedEventDetails{
		Error: new(api.SensitiveError(failure.Name)), Cause: new(api.SensitiveCause(failure.Cause)),
		Location: new(api.EvaluationFailureLocation(failure.Location)), State: new(api.StateName(frame.StateName)),
	}
	id, err := s.appendHistory(tx, execution, revision, at, frameHistory(frame, event))
	if err != nil {
		return err
	}
	frame.PreviousHistoryID = id
	return nil
}
