package stepfunctions

import (
	"context"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awswire"
)

func (s *Service) registerTaskOperations() {
	registerTaskCallback(s, "SendTaskSuccess", s.sendTaskSuccess)
	registerTaskCallback(s, "SendTaskFailure", s.sendTaskFailure)
	registerTaskCallback(s, "SendTaskHeartbeat", s.sendTaskHeartbeat)
	s.operations["GetActivityTask"] = func(ctx context.Context, input any) (any, *awswire.Error) {
		output, err := s.getActivityTask(ctx, input.(*api.GetActivityTaskInput))
		return output, wireError(err)
	}
}

var errTaskNotSubmitted = errors.New("task integration has not acknowledged submission")

func registerTaskCallback[I, O any](s *Service, action string, fn func(Transaction, *I, *transitionEffects) (*O, error)) {
	s.operations[action] = func(ctx context.Context, input any) (any, *awswire.Error) {
		for {
			s.mu.Lock()
			changed, closed := s.changed, s.closed
			s.mu.Unlock()
			if closed {
				return nil, wireError(context.Canceled)
			}
			var output *O
			var effects transitionEffects
			err := s.repository.Attempt(ctx, func(tx Transaction) error {
				var err error
				output, err = fn(tx, input.(*I), &effects)
				if err != nil {
					return err
				}
				return s.recordCall(tx.Context(), action, input, output, nil)
			})
			if errors.Is(err, errTaskNotSubmitted) {
				// A destination can expose the token before its response returns.
				// Wait outside the transaction rather than committing terminal
				// history before TaskSubmitted or rejecting a valid live token.
				select {
				case <-ctx.Done():
					return nil, wireError(ctx.Err())
				case <-s.ctx.Done():
					return nil, wireError(s.ctx.Err())
				case <-changed:
					continue
				}
			}
			if err == nil {
				s.applyEffects(effects)
			}
			// Expired callbacks cannot renew deadlines ahead of the job runner.
			s.notify()
			return output, wireError(err)
		}
	}
}

// getActivityTask releases the transaction before waiting and snapshots the
// change channel before checking the queue, preventing lost lease wakeups.
func (s *Service) getActivityTask(ctx context.Context, in *api.GetActivityTaskInput) (*api.GetActivityTaskOutput, error) {
	if in.ActivityArn == nil || value(in.ActivityArn) == "" {
		return nil, invalid("The activityArn field is required.")
	}
	if utf8.RuneCountInString(value(in.WorkerName)) > 80 {
		return nil, invalid("The workerName field must not exceed 80 characters.")
	}
	deadline := s.clock.Now().Add(60 * time.Second)
	timer := s.clock.NewTimerAt(deadline)
	defer timer.Stop()
	for {
		s.mu.Lock()
		changed, closed := s.changed, s.closed
		s.mu.Unlock()
		if closed {
			return nil, context.Canceled
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var output *api.GetActivityTaskOutput
		var effects transitionEffects
		err := s.repository.Attempt(ctx, func(tx Transaction) error {
			activity, err := s.controlActivity(tx, value(in.ActivityArn), "GetActivityTask")
			if err != nil {
				return err
			}
			at := s.clock.Now().UTC()
			if !at.Before(deadline) {
				output = &api.GetActivityTaskOutput{}
				return s.recordCall(tx.Context(), "GetActivityTask", in, output, nil)
			}
			output, err = s.leaseActivityTask(tx, activity, value(in.WorkerName), at, &effects)
			if err != nil || output == nil {
				return err
			}
			return s.recordCall(tx.Context(), "GetActivityTask", in, output, nil)
		})
		if err != nil {
			return nil, err
		}
		s.applyEffects(effects)
		if len(effects.cancel) != 0 {
			s.notify()
		}
		if output != nil {
			s.notify()
			return output, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-changed:
		case <-timer.C():
		}
	}
}

func (s *Service) leaseActivityTask(tx Transaction, activity ActivityRecord, worker string, at time.Time, effects *transitionEffects) (*api.GetActivityTaskOutput, error) {
	tasks, err := tx.ActivityTasks(activity.Key)
	if err != nil {
		return nil, err
	}
	for _, task := range tasks {
		// The ARN includes the task's actual activity scope; an identically
		// named activity in a different region/account cannot lease its task.
		if task.Resource != activity.Key.ARN() || task.Kind != "activity" || task.Status != TaskScheduled {
			continue
		}
		execution, err := tx.Execution(task.Frame.Execution)
		if err != nil {
			return nil, err
		}
		if !execution.Deadline.After(at) {
			continue
		}
		frame, current, err := currentTask(tx, execution, task)
		if err != nil {
			return nil, err
		}
		if !current {
			continue
		}
		revision, err := tx.Revision(RevisionKey{Scope: execution.Key.Scope, ID: execution.RevisionID})
		if err != nil {
			return nil, err
		}
		input := task.Parameters
		if task.EncryptedInput != nil {
			reader := payloadReader{service: s, reader: tx, revision: revision}
			plain, err := reader.open(activity.Key.ARN(), task.EncryptedInput)
			if err != nil {
				return nil, err
			}
			input = string(plain)
		}
		terminated, err := s.transitionExecution(tx, &execution, revision, at, effects, func(tx Transaction) error {
			task.Status, task.WorkerName = TaskRunning, worker
			startTaskClock(&task, at)
			if err := s.taskStartedHistory(tx, &execution, revision, &frame, &task, at); err != nil {
				return err
			}
			task.Version++
			if err := tx.PutTask(task); err != nil {
				return err
			}
			frame.Version++
			return tx.PutFrame(frame)
		})
		if err != nil {
			return nil, err
		}
		execution.Version++
		if err := tx.PutExecution(execution); err != nil {
			return nil, err
		}
		if terminated {
			continue
		}
		return &api.GetActivityTaskOutput{Input: new(api.SensitiveDataJobInput(input)), TaskToken: new(api.TaskToken(task.Token))}, nil
	}
	return nil, nil
}

func (s *Service) callbackToken(r Reader, token *api.TaskToken, action string) (TaskRecord, error) {
	if token == nil || *token == "" || utf8.RuneCountInString(string(*token)) > 2048 {
		return TaskRecord{}, invalid("The taskToken field must contain between 1 and 2048 characters.")
	}
	if denied := s.authorize(r, action, "*", nil, nil); denied != nil {
		return TaskRecord{}, denied
	}
	task, err := r.TaskByToken(scopeFor(r.Context()), string(*token))
	if errors.Is(err, ErrNotFound) {
		return TaskRecord{}, failure("InvalidToken", "Invalid Token: 'Invalid token'", 400)
	}
	if err != nil {
		return TaskRecord{}, err
	}
	if task.Kind != "activity" && task.Kind != "callback" {
		return TaskRecord{}, failure("InvalidToken", "Invalid Token: 'Invalid token'", 400)
	}
	return task, nil
}

func taskTokenClosed(task TaskRecord) error {
	return failure("TaskTimedOut", "Task Timed Out: '"+task.Resource+"'", 400)
}

func liveCallback(r Reader, task TaskRecord, at time.Time) (ExecutionRecord, FrameRecord, error) {
	if task.Status != TaskRunning && task.Status != TaskSubmitted {
		return ExecutionRecord{}, FrameRecord{}, taskTokenClosed(task)
	}
	execution, err := r.Execution(task.Frame.Execution)
	if errors.Is(err, ErrNotFound) {
		return ExecutionRecord{}, FrameRecord{}, taskTokenClosed(task)
	}
	if err != nil {
		return ExecutionRecord{}, FrameRecord{}, err
	}
	frame, current, err := currentTask(r, execution, task)
	if err != nil {
		return ExecutionRecord{}, FrameRecord{}, err
	}
	if !current || !execution.Deadline.After(at) || (task.Deadline != nil && !task.Deadline.After(at)) || (task.HeartbeatDeadline != nil && !task.HeartbeatDeadline.After(at)) {
		return ExecutionRecord{}, FrameRecord{}, taskTokenClosed(task)
	}
	return execution, frame, nil
}

func (s *Service) sendTaskSuccess(tx Transaction, in *api.SendTaskSuccessInput, effects *transitionEffects) (*api.SendTaskSuccessOutput, error) {
	// Required/shape validation precedes token lookup. Native token identity
	// precedes output JSON validation, but token closure follows it.
	if in.Output == nil || value(in.Output) == "" || len(value(in.Output)) > executionDataLimit {
		return nil, invalid("The output field must contain between 1 and 262144 bytes.")
	}
	task, err := s.callbackToken(tx, in.TaskToken, "SendTaskSuccess")
	if err != nil {
		return nil, err
	}
	if !json.Valid([]byte(*in.Output)) {
		return nil, failure("InvalidOutput", "Invalid output: 'Output is not valid JSON.'", 400)
	}
	at := s.clock.Now().UTC()
	execution, frame, err := liveCallback(tx, task, at)
	if err != nil {
		return nil, err
	}
	if task.Kind == "callback" && task.Status == TaskRunning {
		return nil, errTaskNotSubmitted
	}
	revision, err := tx.Revision(RevisionKey{Scope: execution.Key.Scope, ID: execution.RevisionID})
	if err != nil {
		return nil, err
	}
	tx = s.workflowTransaction(tx, revision, revision.RoleARN)
	task.Status, task.Output = TaskSucceeded, string(*in.Output)
	_, err = s.transitionExecution(tx, &execution, revision, at, effects, func(tx Transaction) error {
		return s.closeTask(tx, &execution, revision, &frame, &task, at, effects)
	})
	if err != nil {
		return nil, err
	}
	execution.Version++
	if err := tx.PutExecution(execution); err != nil {
		return nil, err
	}
	return &api.SendTaskSuccessOutput{}, nil
}

func (s *Service) sendTaskFailure(tx Transaction, in *api.SendTaskFailureInput, effects *transitionEffects) (*api.SendTaskFailureOutput, error) {
	if utf8.RuneCountInString(value(in.Error)) > 256 || utf8.RuneCountInString(value(in.Cause)) > 32768 {
		return nil, invalid("The error field must not exceed 256 characters and cause must not exceed 32768 characters.")
	}
	task, err := s.callbackToken(tx, in.TaskToken, "SendTaskFailure")
	if err != nil {
		return nil, err
	}
	at := s.clock.Now().UTC()
	execution, frame, err := liveCallback(tx, task, at)
	if err != nil {
		return nil, err
	}
	if task.Kind == "callback" && task.Status == TaskRunning {
		return nil, errTaskNotSubmitted
	}
	revision, err := tx.Revision(RevisionKey{Scope: execution.Key.Scope, ID: execution.RevisionID})
	if err != nil {
		return nil, err
	}
	if in.Error == nil && in.Cause == nil {
		// The API accepts an empty failure without KMS authority. Its history
		// belongs to the runtime transition, which may itself fail to decrypt.
		task.Status, task.Encrypted = TaskFailurePending, nil
		if err := retainTaskCompletion(tx, &frame, &task, at, effects); err != nil {
			return nil, err
		}
		return &api.SendTaskFailureOutput{}, nil
	}
	tx = s.workflowTransaction(tx, revision, revision.RoleARN)
	task.Status, task.Error, task.Cause = TaskFailed, value(in.Error), value(in.Cause)
	_, err = s.transitionExecution(tx, &execution, revision, at, effects, func(tx Transaction) error {
		return s.closeTask(tx, &execution, revision, &frame, &task, at, effects)
	})
	if err != nil {
		return nil, err
	}
	execution.Version++
	if err := tx.PutExecution(execution); err != nil {
		return nil, err
	}
	return &api.SendTaskFailureOutput{}, nil
}

func (s *Service) sendTaskHeartbeat(tx Transaction, in *api.SendTaskHeartbeatInput, _ *transitionEffects) (*api.SendTaskHeartbeatOutput, error) {
	task, err := s.callbackToken(tx, in.TaskToken, "SendTaskHeartbeat")
	if err != nil {
		return nil, err
	}
	at := s.clock.Now().UTC()
	// Branch cancellation revokes completion immediately, but the already
	// issued heartbeat lease can still be acknowledged until its original
	// deadline. It is never renewed and explicit execution stops clear it.
	if task.Status == TaskCancelled && task.HeartbeatDeadline != nil && task.HeartbeatDeadline.After(at) {
		frame, err := tx.Frame(task.Frame)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if err == nil && frame.ParentID != 0 && frame.Phase == FrameAborted {
			return &api.SendTaskHeartbeatOutput{}, nil
		}
	}
	if _, _, err := liveCallback(tx, task, at); err != nil {
		return nil, err
	}
	if task.HeartbeatSeconds > 0 {
		task.HeartbeatDeadline = new(at.Add(time.Duration(task.HeartbeatSeconds) * time.Second))
		task.Version++
		if err := tx.PutTask(task); err != nil {
			return nil, err
		}
	}
	return &api.SendTaskHeartbeatOutput{}, nil
}
