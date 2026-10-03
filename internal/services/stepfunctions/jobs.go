package stepfunctions

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/scheduler"
)

type workflowJobs struct{ s *Service }

// transitionEffects contains only work that must follow a successful commit.
// Resource state and deadlines stay authoritative in the repository.
type transitionEffects struct {
	cancel []TaskKey
	launch *taskLaunch
}

type taskLaunch struct {
	task      TaskRecord
	revision  RevisionRecord
	execution ExecutionRecord
	stateID   int64
}

func (j workflowJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	if !j.s.recovered {
		return scheduler.Job{Key: "stepfunctions:recover", Version: 1, Due: time.Unix(0, 0)}, true, nil
	}
	var next WorkRecord
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		next, err = r.NextWork()
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return scheduler.Job{}, false, nil
	}
	return scheduler.Job{Key: next.Key(), Version: uint64(next.Version), Due: next.Due}, err == nil, err
}

func (j workflowJobs) Run(ctx context.Context, selected scheduler.Job) error {
	if selected.Key == "stepfunctions:recover" {
		return j.recover(ctx)
	}
	if strings.HasPrefix(selected.Key, string(WorkHistoryDelivery)+"|") {
		return j.s.deliverHistory(ctx, selected)
	}
	var effects transitionEffects
	err := j.s.repository.Update(ctx, func(tx Transaction) error {
		work, err := tx.NextWork()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if work.Key() != selected.Key || uint64(work.Version) != selected.Version || !work.Due.Equal(selected.Due) {
			return nil
		}
		if work.Kind == WorkMachineDelete {
			return tx.DeleteMachine(work.Machine)
		}
		if work.Kind == WorkExecutionExpiry {
			return tx.DeleteExecution(work.Execution)
		}
		execution, err := tx.Execution(work.Execution)
		if err != nil {
			return err
		}
		revision, err := tx.Revision(RevisionKey{Scope: execution.Key.Scope, ID: execution.RevisionID})
		if err != nil {
			return err
		}
		var admitted []HistoryRecord
		err = j.s.repository.Attempt(tx.Context(), func(command Transaction) error {
			working := j.s.workflowTransaction(command, revision, revision.RoleARN)
			active, err := working.reader.execution(execution)
			if err != nil {
				return err
			}
			definition, err := working.Revision(revision.Key)
			if err != nil {
				return err
			}
			captured := false
			_, err = j.s.transitionExecution(working, &active, definition, work.Due, &effects, func(tx Transaction) error {
				err := j.runExecutionWork(tx, &active, definition, work, &effects)
				if executionEncryptionFailure(err) != nil {
					captured = true
					var readErr error
					admitted, readErr = failedWorkHistory(tx, execution.NextHistoryID, active)
					if readErr != nil {
						return readErr
					}
				}
				return err
			})
			if err == nil {
				active.Version++
				err = working.PutExecution(active)
			}
			if executionEncryptionFailure(err) != nil && !captured {
				var readErr error
				admitted, readErr = failedWorkHistory(command, execution.NextHistoryID, active)
				if readErr != nil {
					return readErr
				}
			}
			return err
		})
		if err == nil {
			return nil
		}
		rejected := executionEncryptionFailure(err)
		if rejected == nil {
			return err
		}
		// The unsuccessful attempt cannot launch or cancel external work.
		// Keep only history that was formed before payload access
		// failed, including its opaque ciphertext.
		effects = transitionEffects{}
		for _, record := range admitted {
			if err := tx.AppendHistory(record); err != nil {
				return err
			}
			execution.NextHistoryID = int64(*record.Event.Id)
		}
		if err := j.s.failExecutionEncryption(tx, &execution, revision, rejected, work.Due, &effects); err != nil {
			return err
		}
		execution.Version++
		return tx.PutExecution(execution)
	})
	if err != nil {
		return err
	}
	j.s.applyEffects(effects)
	j.s.notify()
	return nil
}

func (j workflowJobs) runExecutionWork(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, work WorkRecord, effects *transitionEffects) error {
	switch work.Kind {
	case WorkExecutionTimeout:
		return j.s.endExecution(tx, execution, revision, "TIMED_OUT", "", "", "", work.Due, effects)
	case WorkFrame:
		frame, err := tx.Frame(FrameKey{Execution: execution.Key, ID: work.FrameID})
		if err != nil {
			return err
		}
		if execution.Type == "STANDARD" && frame.Phase == FrameReady {
			quota, _ := workflowQuotaFor("StateTransition", execution.Key.Scope.Region)
			// Entries and ASL retries consume transitions; task callbacks,
			// Wait completion, joins and deadlines do not. Use the scheduled
			// service time, just as the resulting history does.
			if delay := j.s.admission.admit(execution.Key.Scope, "StateTransition", work.Due, quota); delay > 0 {
				due := work.Due.Add(delay)
				frame.Due = &due
				frame.Version++
				if err := tx.PutFrame(frame); err != nil {
					return err
				}
				return j.s.executionThrottledMetrics(tx.Context(), *execution, work.Due)
			}
		}
		return j.s.runFrame(tx, execution, revision, frame, work.Due, effects)
	case WorkTaskDispatch:
		return j.s.dispatchTask(tx, execution, revision, TaskKey{Scope: execution.Key.Scope, ID: work.TaskID}, work.Due, effects)
	case WorkTaskTimeout, WorkHeartbeatTimeout:
		task, err := tx.Task(TaskKey{Scope: execution.Key.Scope, ID: work.TaskID})
		if err != nil {
			return err
		}
		return j.s.timeoutTask(tx, execution, revision, task, work.Kind, work.Due, effects)
	}
	return nil
}

func failedWorkHistory(tx Transaction, after int64, execution ExecutionRecord) ([]HistoryRecord, error) {
	if working, ok := tx.(*workflowTransaction); ok {
		tx = working.Transaction
	}
	var admitted []HistoryRecord
	for id := after + 1; id <= execution.NextHistoryID; id++ {
		record, err := tx.HistoryEvent(execution.Key, id)
		// appendHistory reserves the ID before sealing its event. A failed
		// seal leaves no event to retain.
		if errors.Is(err, ErrNotFound) && id == execution.NextHistoryID {
			break
		}
		if err != nil {
			return nil, err
		}
		switch value(record.Event.Type) {
		case "ExecutionSucceeded", "ExecutionFailed", "ExecutionAborted", "ExecutionTimedOut":
			// A terminal result whose enclosing transition did not commit
			// must not precede the actual KMS terminal failure.
			return admitted, nil
		}
		admitted = append(admitted, record)
	}
	return admitted, nil
}

func (j workflowJobs) recover(ctx context.Context) error {
	err := j.s.repository.Update(ctx, func(tx Transaction) error {
		tasks, err := tx.RecoverableTasks()
		if err != nil {
			return err
		}
		for _, task := range tasks {
			// Retain the attempt identity, original start and deadline. A
			// recovered external effect is not a new ASL Retry attempt.
			task.Status = TaskScheduled
			task.Version++
			if err := tx.PutTask(task); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		j.s.recovered = true
	}
	return err
}

func (s *Service) applyEffects(effects transitionEffects) {
	s.mu.Lock()
	for _, key := range effects.cancel {
		if cancel := s.active[key]; cancel != nil {
			cancel()
		}
	}
	s.mu.Unlock()
	if effects.launch != nil {
		s.launchTask(*effects.launch)
	}
}
