package stepfunctions

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strings"
	"time"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awswire"
	"stackd/internal/services/stepfunctions/asl"
)

func executionEncryptionFailure(err error) *awswire.Error {
	var rejected *awswire.Error
	if errors.As(err, &rejected) && strings.HasPrefix(rejected.Code, "Kms") {
		return rejected
	}
	return nil
}

// failExecutionEncryption runs against raw records after the failed payload
// transition has rolled back. No customer payload needs to be opened or sealed
// to revoke work and retain the service-generated KMS diagnostic.
func (s *Service) failExecutionEncryption(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, rejected *awswire.Error, at time.Time, effects *transitionEffects) error {
	_, err := s.transitionExecution(tx, execution, revision, at, effects, func(tx Transaction) error {
		return s.endExecution(tx, execution, revision, "FAILED", "", "States.Runtime", rejected.Message, at, effects)
	})
	return err
}

func matchesStateError(patterns []string, name string) bool {
	if name == "States.Runtime" {
		return false
	}
	for _, pattern := range patterns {
		if pattern == name || pattern == "States.ALL" && name != "States.DataLimitExceeded" || pattern == "States.TaskFailed" && name != "States.Timeout" && name != "States.DataLimitExceeded" {
			return true
		}
	}
	return false
}

// retryDue bounds arithmetic by the execution deadline, not by a silently
// saturated duration. A retry scheduled at that boundary loses to the timeout.
func retryDue(retrier asl.Retrier, count int64, env asl.Environment, at, deadline time.Time) (time.Time, error) {
	delay := float64(retrier.IntervalSeconds) * math.Pow(retrier.BackoffRate, float64(count))
	if retrier.MaxDelaySeconds > 0 {
		delay = math.Min(delay, float64(retrier.MaxDelaySeconds))
	}
	if retrier.JitterStrategy == "FULL" {
		var random [8]byte
		if _, err := io.ReadFull(env.Random, random[:]); err != nil {
			return time.Time{}, err
		}
		fraction := float64(binary.LittleEndian.Uint64(random[:])>>11) / (1 << 53)
		if fraction == 0 {
			delay = 0
		} else {
			delay *= fraction
		}
	}
	if delay >= deadline.Sub(at).Seconds() {
		return deadline, nil
	}
	return at.Add(time.Duration(delay * float64(time.Second))), nil
}

func (s *Service) failState(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, name, cause string, at time.Time, effects *transitionEffects) error {
	if name == "States.Runtime" {
		frame.Phase, frame.Error, frame.Cause, frame.Due = FrameFailed, name, cause, nil
		if err := tx.PutFrame(*frame); err != nil {
			return err
		}
		return s.endExecution(tx, execution, revision, "FAILED", "", name, cause, at, effects)
	}
	if (state.Type == asl.Map || state.Type == asl.Parallel) && frame.Phase != FrameReady {
		if state.Type == asl.Map {
			if err := s.failMapRun(tx, execution, revision, frame, name, cause, at); err != nil {
				return err
			}
		}
		if err := s.abortDescendants(tx, execution, revision, frame, at, effects); err != nil {
			return err
		}
		record := frameHistory(frame, historyEvent(string(state.Type)+"StateFailed", frame.PreviousHistoryID))
		record.Error, record.Cause = name, cause
		id, err := s.appendHistory(tx, execution, revision, at, record)
		if err != nil {
			return err
		}
		frame.PreviousHistoryID = id
	}
	for i, retrier := range state.Retry {
		if !matchesStateError(retrier.ErrorEquals, name) {
			continue
		}
		count := frame.RetryCounts[i]
		if count >= retrier.MaxAttempts {
			break
		}
		due, err := retryDue(retrier, count, env, at, execution.Deadline)
		if err != nil {
			return err
		}
		if frame.RetryCounts == nil {
			frame.RetryCounts = make(map[int]int64)
		}
		frame.RetryCounts[i] = count + 1
		frame.RetryCount++
		frame.Phase, frame.Due, frame.TaskID = FrameReady, new(due), ""
		frame.Arguments, frame.Error, frame.Cause = "", "", ""
		frame.NextItem, frame.ItemCount, frame.MaxConcurrency, frame.MapRunARN = 0, 0, 0, ""
		return nil
	}
	for _, catcher := range state.Catch {
		if !matchesStateError(catcher.ErrorEquals, name) {
			continue
		}
		var assigned api.AssignedVariables
		encoded, variables, err := evaluateCatch(tx.Context(), state, env, catcher, name, cause, inspectAssignments(&assigned))
		if err == nil {
			err = applyFrameVariables(tx, frame, variables)
		}
		if err != nil {
			var evaluation *asl.EvaluationError
			if !errors.As(err, &evaluation) {
				return err
			}
			if err := s.recordEvaluationFailure(tx, execution, revision, frame, evaluation, at); err != nil {
				return err
			}
			name, cause = evaluation.Name, evaluation.Cause
			break
		}
		if err := s.stateExited(tx, execution, revision, frame, string(state.Type), encoded, assigned, at); err != nil {
			return err
		}
		frame.StateName, frame.Input, frame.Phase, frame.Due = catcher.Next, encoded, FrameReady, new(at)
		frame.EnteredHistoryID, frame.RetryCount = 0, 0
		frame.RetryCounts, frame.TaskID, frame.Arguments = nil, "", ""
		frame.NextItem, frame.ItemCount, frame.MaxConcurrency, frame.MapRunARN = 0, 0, 0, ""
		return nil
	}
	frame.Phase, frame.Error, frame.Cause, frame.Due = FrameFailed, name, cause, nil
	if frame.ParentID != 0 {
		return s.childFinished(tx, execution, revision, *frame, at, effects)
	}
	if err := tx.PutFrame(*frame); err != nil {
		return err
	}
	return s.endExecution(tx, execution, revision, "FAILED", "", name, cause, at, effects)
}
