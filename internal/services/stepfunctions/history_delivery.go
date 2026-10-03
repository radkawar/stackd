package stepfunctions

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"stackd/internal/scheduler"
)

// deliverHistory consumes retained history for Logs and X-Ray without a second
// payload queue. Observation is best effort; a crash before cursor commit may
// repeat publication but cannot change the workflow's execution outcome.
func (s *Service) deliverHistory(ctx context.Context, selected scheduler.Job) error {
	var execution ExecutionRecord
	var revision RevisionRecord
	var record HistoryRecord
	var documents []TraceDocument
	var traceErr error
	var payloadErr error
	ready := false
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		var r Reader = tx
		work, err := r.NextWork()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if work.Key() != selected.Key || uint64(work.Version) != selected.Version || !work.Due.Equal(selected.Due) {
			return nil
		}
		execution, err = r.Execution(work.Execution)
		if err != nil {
			return err
		}
		revision, err = r.Revision(RevisionKey{Scope: execution.Key.Scope, ID: execution.RevisionID})
		if err != nil {
			return err
		}
		record, err = r.HistoryEvent(execution.Key, execution.DeliveredHistoryID+1)
		if err != nil {
			return err
		}
		working := s.workflowReader(r, revision, revision.RoleARN)
		working.fixed = s.encryption.synchronousMaterial(execution.Key)
		opened, err := working.history(record)
		if err != nil {
			if executionEncryptionFailure(err) == nil {
				return err
			}
			payloadErr = err
			ready = true
			return nil
		}
		record, r = opened, working
		if execution.TraceSegmentID != "" && s.tracing != nil {
			documents, traceErr = projectTraceHistory(r, record, execution, revision)
		}
		ready = true
		return nil
	}); err != nil || !ready {
		return err
	}
	logging := revision.LogLevel != "" && revision.LogLevel != "OFF"
	if logging && s.history == nil {
		return fmt.Errorf("configured Step Functions logging has no delivery adapter")
	}
	if execution.TraceSegmentID != "" && s.tracing == nil {
		return fmt.Errorf("configured Step Functions tracing has no delivery adapter")
	}
	if payloadErr != nil {
		slog.WarnContext(ctx, "Step Functions history decryption failed", "execution", execution.Key.ARN, "event", *record.Event.Id, "error", payloadErr)
	}
	if logging && payloadErr == nil {
		if err := s.history.PublishHistory(requestContext(ctx, execution), record, execution, revision); err != nil {
			slog.WarnContext(ctx, "Step Functions history delivery failed", "execution", execution.Key.ARN, "event", *record.Event.Id, "error", err)
		}
	}
	if traceErr == nil && len(documents) != 0 {
		traceErr = s.tracing.PublishTrace(requestContext(ctx, execution), revision, documents)
	}
	if traceErr != nil {
		slog.WarnContext(ctx, "Step Functions trace delivery failed", "execution", execution.Key.ARN, "event", *record.Event.Id, "error", traceErr)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Execution(execution.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.MachineID != execution.MachineID || !current.Started.Equal(execution.Started) || current.DeliveredHistoryID != execution.DeliveredHistoryID {
			return nil
		}
		current.DeliveredHistoryID++
		current.Version++
		return tx.PutExecution(current)
	}); err != nil {
		return err
	}
	s.notify()
	return nil
}
