package stepfunctions

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"strings"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/services/stepfunctions/asl"
)

const defaultTaskTimeoutSeconds int64 = 99999999

// prepareTask is shared with TestState; it evaluates the compiled pre-task
// pipeline once, with the token belonging to this attempt already in context.
func prepareTask(ctx context.Context, state *asl.State, env asl.Environment, execution ExecutionRecord, revision RevisionRecord, frame FrameRecord, at time.Time, observers ...stateInspection) (TaskRecord, error) {
	var tokenBytes [64]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return TaskRecord{}, err
	}
	task := TaskRecord{
		Key: TaskKey{Scope: execution.Key.Scope, ID: uuid.NewString()}, Frame: frame.Key,
		Attempt: frame.RetryCount, Token: base64.RawURLEncoding.EncodeToString(tokenBytes[:]),
		Kind: "task", Resource: state.Task.Resource, RoleARN: revision.RoleARN,
		Status: TaskScheduled, Scheduled: at, TimeoutSeconds: defaultTaskTimeoutSeconds, Version: 1,
	}
	parts := strings.SplitN(task.Resource, ":", 6)
	if len(parts) == 6 {
		switch {
		case parts[2] == "states" && strings.HasPrefix(parts[5], "activity:"):
			task.Kind, task.Activity = "activity", strings.TrimPrefix(parts[5], "activity:")
		case parts[2] == "lambda":
			task.Kind = "lambda"
		case strings.HasSuffix(task.Resource, ".waitForTaskToken"):
			task.Kind = "callback"
		case strings.HasSuffix(task.Resource, ".sync"), strings.HasSuffix(task.Resource, ".sync:2"):
			task.Kind = "sync"
		}
	}
	env.ContextObject = maps.Clone(env.ContextObject)
	if env.ContextObject == nil {
		env.ContextObject = make(map[string]any)
	}
	env.ContextObject["Task"] = map[string]any{"Token": task.Token}
	arguments, err := stateArguments(ctx, state, env, observers...)
	if err != nil {
		return TaskRecord{}, err
	}
	task.Parameters, err = encodeExecutionData(arguments)
	if err != nil {
		return TaskRecord{}, err
	}
	// JSONPath scalar paths address the state input selected by InputPath, not
	// the newly constructed Parameters document.
	if state.Language == asl.JSONPath {
		env.Input, err = selectedInput(state.InputPath, env)
		if err != nil {
			return TaskRecord{}, err
		}
	}
	if state.Task.TimeoutSeconds != nil {
		task.TimeoutSeconds, err = state.Task.TimeoutSeconds.Evaluate(ctx, env)
		if err != nil {
			return TaskRecord{}, err
		}
	}
	if state.Task.HeartbeatSeconds != nil {
		task.HeartbeatSeconds, err = state.Task.HeartbeatSeconds.Evaluate(ctx, env)
		if err != nil {
			return TaskRecord{}, err
		}
	}
	if state.Task.Credentials != nil {
		task.RoleARN, err = state.Task.Credentials.RoleArn.Evaluate(ctx, env)
		if err != nil {
			return TaskRecord{}, err
		}
	}
	return task, nil
}

func (s *Service) scheduleTask(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, at time.Time) error {
	task, err := prepareTask(tx.Context(), state, env, *execution, revision, *frame, at)
	if err != nil {
		return err
	}
	if err := s.protectTaskInput(tx, revision, &task); err != nil {
		return err
	}
	if err := s.taskScheduledHistory(tx, execution, revision, frame, &task, state.Task, at); err != nil {
		return err
	}
	frame.Phase, frame.TaskID, frame.Arguments, frame.Due = FrameTask, task.Key.ID, task.Parameters, nil
	return tx.PutTask(task)
}

func (s *Service) scheduleMapEffect(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, kind, resource, parameters string, at time.Time) error {
	task := TaskRecord{
		Key: TaskKey{Scope: execution.Key.Scope, ID: uuid.NewString()}, Frame: frame.Key,
		Attempt: frame.RetryCount, Kind: kind, Resource: resource, Parameters: parameters,
		RoleARN: revision.RoleARN, Status: TaskScheduled, Scheduled: at,
		TimeoutSeconds: defaultTaskTimeoutSeconds, Version: 1,
	}
	if err := s.protectTaskInput(tx, revision, &task); err != nil {
		return err
	}
	frame.Phase, frame.TaskID, frame.Due = FrameTask, task.Key.ID, nil
	return tx.PutTask(task)
}

func mapTask(task TaskRecord) bool {
	return task.Kind == "MAP_READER" || task.Kind == "MAP_WRITER" || task.Kind == "MAP_EXECUTIONS" || task.Kind == "MAP_REDRIVE"
}

// currentTask fences both the attempt and every enclosing branch generation.
// A late effect from an aborted branch cannot land in a retried parent state.
func currentTask(r Reader, execution ExecutionRecord, task TaskRecord) (FrameRecord, bool, error) {
	if execution.Status != "RUNNING" || task.Frame.Execution != execution.Key {
		return FrameRecord{}, false, nil
	}
	frame, err := r.Frame(task.Frame)
	if errors.Is(err, ErrNotFound) {
		return FrameRecord{}, false, nil
	}
	if err != nil {
		return FrameRecord{}, false, err
	}
	if frame.Phase != FrameTask || frame.TaskID != task.Key.ID || frame.RetryCount != task.Attempt {
		return frame, false, nil
	}
	for child := frame; child.ParentID != 0; {
		parent, err := r.Frame(FrameKey{Execution: execution.Key, ID: child.ParentID})
		if errors.Is(err, ErrNotFound) {
			return frame, false, nil
		}
		if err != nil {
			return frame, false, err
		}
		if parent.Phase != FrameJoining || !currentChild(parent, child) {
			return frame, false, nil
		}
		child = parent
	}
	return frame, true, nil
}

func taskOpen(task TaskRecord) bool {
	return task.Status == TaskScheduled || task.Status == TaskRunning || task.Status == TaskSubmitted
}

func (s *Service) resumeTask(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, at time.Time, effects *transitionEffects) error {
	task, err := tx.Task(TaskKey{Scope: execution.Key.Scope, ID: frame.TaskID})
	if err != nil {
		return err
	}
	if taskOpen(task) || task.Status == TaskCancelled {
		return nil
	}
	if task.Status == TaskFailurePending {
		task.Status = TaskFailed
		if err := s.taskClosedHistory(tx, execution, revision, frame, &task, at); err != nil {
			return err
		}
		task.Version++
		if err := tx.PutTask(task); err != nil {
			return err
		}
	}
	if mapTask(task) {
		return s.resumeMapEffect(tx, execution, revision, frame, state, env, task, at, effects)
	}
	env.ContextObject = maps.Clone(env.ContextObject)
	if env.ContextObject == nil {
		env.ContextObject = make(map[string]any)
	}
	env.ContextObject["Task"] = map[string]any{"Token": task.Token}
	if task.Status != TaskSucceeded {
		return s.failState(tx, execution, revision, frame, state, env, task.Error, task.Cause, at, effects)
	}
	var result any
	if err := json.Unmarshal([]byte(task.Output), &result); err != nil {
		return &asl.EvaluationError{Name: "States.Runtime", Cause: "The task returned invalid JSON: " + err.Error()}
	}
	return s.finishState(tx, execution, revision, frame, state, env, result, state.Next, state.Assign, state.Output, at, effects)
}

func startTaskClock(task *TaskRecord, at time.Time) {
	if task.Started != nil {
		return
	}
	task.Started = new(at)
	if task.TimeoutSeconds > 0 {
		task.Deadline = new(at.Add(time.Duration(task.TimeoutSeconds) * time.Second))
	}
	if task.HeartbeatSeconds > 0 {
		task.HeartbeatDeadline = new(at.Add(time.Duration(task.HeartbeatSeconds) * time.Second))
	}
}

func (s *Service) dispatchTask(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, key TaskKey, at time.Time, effects *transitionEffects) error {
	task, err := tx.Task(key)
	if err != nil {
		return err
	}
	if task.Status != TaskScheduled || task.Kind == "activity" {
		return nil
	}
	frame, current, err := currentTask(tx, *execution, task)
	if err != nil {
		return err
	}
	if !current {
		task.Status, task.Deadline, task.HeartbeatDeadline = TaskCancelled, nil, nil
		task.Version++
		return tx.PutTask(task)
	}
	firstStart := task.Started == nil
	startTaskClock(&task, at)
	task.Status = TaskRunning
	if task.Kind == "sync" && task.Output != "" {
		task.Status = TaskSubmitted
	}
	if firstStart {
		if err := s.taskStartedHistory(tx, execution, revision, &frame, &task, at); err != nil {
			return err
		}
	}
	task.Version++
	if err := tx.PutTask(task); err != nil {
		return err
	}
	frame.Version++
	if err := tx.PutFrame(frame); err != nil {
		return err
	}
	effects.launch = &taskLaunch{task: task, revision: revision, execution: *execution, stateID: frame.EnteredHistoryID}
	return nil
}

func (s *Service) timeoutTask(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, task TaskRecord, kind WorkKind, at time.Time, effects *transitionEffects) error {
	if task.Status != TaskRunning && task.Status != TaskSubmitted {
		return nil
	}
	deadline := task.Deadline
	if kind == WorkHeartbeatTimeout {
		deadline = task.HeartbeatDeadline
	}
	if deadline == nil || deadline.After(at) {
		return nil
	}
	frame, current, err := currentTask(tx, *execution, task)
	if err != nil || !current {
		return err
	}
	// Activity heartbeat failures are native States.Timeout as well; heartbeat
	// renewal never moves the independently retained absolute task deadline.
	task.Status, task.Error, task.Cause = TaskTimedOut, "States.Timeout", ""
	return s.closeTask(tx, execution, revision, &frame, &task, *deadline, effects)
}

func (s *Service) closeTask(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, task *TaskRecord, at time.Time, effects *transitionEffects) error {
	if err := s.taskClosedHistory(tx, execution, revision, frame, task, at); err != nil {
		return err
	}
	return retainTaskCompletion(tx, frame, task, at, effects)
}

func retainTaskCompletion(tx Transaction, frame *FrameRecord, task *TaskRecord, at time.Time, effects *transitionEffects) error {
	task.Deadline, task.HeartbeatDeadline = nil, nil
	task.Version++
	if err := tx.PutTask(*task); err != nil {
		return err
	}
	frame.Due = new(at)
	frame.Version++
	if err := tx.PutFrame(*frame); err != nil {
		return err
	}
	effects.cancel = append(effects.cancel, task.Key)
	return nil
}

// expiredTask uses authoritative absolute deadlines even when a callback or
// destination completes before the scheduler has selected the due timeout.
func (s *Service) expiredTask(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, task TaskRecord, at time.Time, effects *transitionEffects) (bool, error) {
	due, kind := task.Deadline, WorkTaskTimeout
	if task.HeartbeatDeadline != nil && (due == nil || task.HeartbeatDeadline.Before(*due)) {
		due, kind = task.HeartbeatDeadline, WorkHeartbeatTimeout
	}
	if !execution.Deadline.After(at) && (due == nil || !execution.Deadline.After(*due)) {
		return true, s.endExecution(tx, execution, revision, "TIMED_OUT", "", "", "", execution.Deadline, effects)
	}
	if due != nil && !due.After(at) {
		return true, s.timeoutTask(tx, execution, revision, task, kind, *due, effects)
	}
	return false, nil
}

// launchTask owns no workflow transaction while invoking a destination. Add is
// serialized with Close's closed flag so Wait cannot race a newly added worker.
func (s *Service) launchTask(launch taskLaunch) {
	s.mu.Lock()
	if s.closed || s.active[launch.task.Key] != nil {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(requestContext(s.ctx, launch.execution))
	ctx = taskTracingContext(ctx, launch.execution, launch.revision, launch.task, launch.stateID)
	s.active[launch.task.Key] = cancel
	s.workers.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.workers.Done()
		defer cancel()
		defer func() {
			s.mu.Lock()
			delete(s.active, launch.task.Key)
			s.mu.Unlock()
		}()
		current, err := s.taskForLaunch(ctx, launch)
		if err != nil {
			if ctx.Err() == nil {
				slog.ErrorContext(ctx, "Step Functions task launch failed", "task", launch.task.Key.ID, "error", err)
			}
			return
		}
		if !current || ctx.Err() != nil {
			return
		}
		submit := func(outcome TaskOutcome) error {
			outcome.Submitted = true
			return s.completeTask(ctx, launch, outcome)
		}
		var outcome TaskOutcome
		err = nil
		if s.tasks == nil {
			outcome = TaskOutcome{Error: "States.TaskFailed", Cause: "No task destination adapter is configured."}
		} else {
			outcome, err = s.tasks.Run(ctx, launch.task, launch.revision, submit)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			outcome = TaskOutcome{Error: "States.TaskFailed", Cause: err.Error()}
		}
		if err := s.completeTask(ctx, launch, outcome); err != nil && ctx.Err() == nil {
			slog.ErrorContext(ctx, "Step Functions task completion failed", "task", launch.task.Key.ID, "error", err)
		}
	}()
}

// taskForLaunch closes the commit-to-launch cancellation window. The active
// cancellation handle is installed before this check, so later aborts cancel
// the exact context the destination sees.
func (s *Service) taskForLaunch(ctx context.Context, launch taskLaunch) (bool, error) {
	var current, expired bool
	err := s.repository.View(ctx, func(r Reader) error {
		task, err := r.Task(launch.task.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if task.Frame != launch.task.Frame || task.Token != launch.task.Token || task.Attempt != launch.task.Attempt || (task.Status != TaskRunning && task.Status != TaskSubmitted) {
			return nil
		}
		execution, err := r.Execution(task.Frame.Execution)
		if err != nil {
			return err
		}
		_, current, err = currentTask(r, execution, task)
		at := s.clock.Now()
		expired = !execution.Deadline.After(at) || (task.Deadline != nil && !task.Deadline.After(at)) || (task.HeartbeatDeadline != nil && !task.HeartbeatDeadline.After(at))
		return err
	})
	if err != nil || !current {
		return false, err
	}
	if expired {
		return false, s.completeTask(ctx, launch, TaskOutcome{})
	}
	return true, nil
}

func taskOutcomeFailure(outcome TaskOutcome, allowLarge bool) TaskOutcome {
	if outcome.Error != "" {
		return outcome
	}
	if !allowLarge && len(outcome.Output) > executionDataLimit {
		outcome.Output, outcome.Error, outcome.Cause = "", "States.DataLimitExceeded", "Task output exceeds the maximum allowed size of 262144 bytes."
	} else if !json.Valid([]byte(outcome.Output)) {
		outcome.Output, outcome.Error, outcome.Cause = "", "States.Runtime", "The task returned invalid JSON."
	}
	return outcome
}

func (s *Service) completeTask(ctx context.Context, launch taskLaunch, outcome TaskOutcome) error {
	outcome = taskOutcomeFailure(outcome, mapTask(launch.task))
	var effects transitionEffects
	rejected := outcome.Submitted
	err := s.repository.Update(ctx, func(tx Transaction) error {
		task, err := tx.Task(launch.task.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if task.Frame != launch.task.Frame || task.Attempt != launch.task.Attempt || task.Token != launch.task.Token || (task.Status != TaskRunning && task.Status != TaskSubmitted) {
			return nil
		}
		execution, err := tx.Execution(task.Frame.Execution)
		if err != nil {
			return err
		}
		frame, current, err := currentTask(tx, execution, task)
		if err != nil || !current {
			return err
		}
		tx = s.workflowTransaction(tx, launch.revision, launch.revision.RoleARN)
		at := s.clock.Now().UTC()
		if task.Kind == "callback" && outcome.Error == "" {
			outcome.Submitted = true
		}
		limited, err := s.transitionExecution(tx, &execution, launch.revision, at, &effects, func(tx Transaction) error {
			expired, err := s.expiredTask(tx, &execution, launch.revision, task, at, &effects)
			if err != nil {
				return err
			}
			if !expired {
				if outcome.Error != "" {
					task.Status, task.Error, task.Cause = TaskFailed, outcome.Error, outcome.Cause
					if task.Kind == "MAP_WRITER" && outcome.Output != "" && json.Valid([]byte(outcome.Output)) {
						task.Output = outcome.Output
					}
				} else if outcome.Submitted {
					if task.Status == TaskSubmitted {
						rejected = false
						return nil
					}
					task.Status, task.Output = TaskSubmitted, outcome.Output
					if err := s.taskSubmittedHistory(tx, &execution, launch.revision, &frame, &task, outcome.Output, at); err != nil {
						return err
					}
					task.Version++
					if err := tx.PutTask(task); err != nil {
						return err
					}
					frame.Version++
					if err := tx.PutFrame(frame); err != nil {
						return err
					}
					rejected = false
				} else {
					task.Status, task.Output = TaskSucceeded, outcome.Output
				}
				if task.Status != TaskSubmitted {
					if err := s.closeTask(tx, &execution, launch.revision, &frame, &task, at, &effects); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if limited && outcome.Submitted {
			// Submission can have created an external job before returning here.
			// Commit cancellation, then reject the submission so its adapter can
			// cancel the job instead of treating it as durably acknowledged.
			rejected = true
		}
		execution.Version++
		return tx.PutExecution(execution)
	})
	if err == nil {
		s.applyEffects(effects)
		s.notify()
	}
	if err == nil && rejected {
		return context.Canceled
	}
	return err
}

func taskResourceNames(task TaskRecord) (string, string) {
	parts := strings.SplitN(task.Resource, ":", 6)
	if len(parts) != 6 {
		return "", task.Resource
	}
	resourceType, resource, found := strings.Cut(parts[5], ":")
	if resourceType == "aws-sdk" {
		service, operation, _ := strings.Cut(resource, ":")
		return "aws-sdk:" + service, operation
	}
	if !found {
		return parts[2], parts[5]
	}
	return resourceType, resource
}

func historyDataDetails() *api.HistoryEventExecutionDataDetails {
	return &api.HistoryEventExecutionDataDetails{Truncated: new(api.Truncated(false))}
}

func (s *Service) taskHistory(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, task *TaskRecord, at time.Time, event api.HistoryEvent) error {
	record := frameHistory(frame, event)
	id, err := s.appendHistory(tx, execution, revision, at, record)
	if err == nil {
		task.HistoryID, frame.PreviousHistoryID = id, id
	}
	return err
}

func (s *Service) taskScheduledHistory(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, task *TaskRecord, config *asl.TaskState, at time.Time) error {
	var credentials *api.TaskCredentials
	if config.Credentials != nil {
		credentials = &api.TaskCredentials{RoleArn: new(api.LongArn(task.RoleARN))}
	}
	var timeout *api.TimeoutInSeconds
	if config.TimeoutSeconds != nil {
		timeout = new(api.TimeoutInSeconds(task.TimeoutSeconds))
	}
	event := historyEvent("TaskScheduled", frame.PreviousHistoryID)
	switch task.Kind {
	case "activity":
		event.Type = new(api.HistoryEventType("ActivityScheduled"))
		event.ActivityScheduledEventDetails = &api.ActivityScheduledEventDetails{
			Resource: new(api.Arn(task.Resource)), Input: new(api.SensitiveData(task.Parameters)),
			InputDetails: historyDataDetails(), TimeoutInSeconds: timeout,
		}
		if task.HeartbeatSeconds > 0 {
			event.ActivityScheduledEventDetails.HeartbeatInSeconds = new(api.TimeoutInSeconds(task.HeartbeatSeconds))
		}
	case "lambda":
		event.Type = new(api.HistoryEventType("LambdaFunctionScheduled"))
		event.LambdaFunctionScheduledEventDetails = &api.LambdaFunctionScheduledEventDetails{
			Resource: new(api.Arn(task.Resource)), Input: new(api.SensitiveData(task.Parameters)),
			InputDetails: historyDataDetails(), TimeoutInSeconds: timeout, TaskCredentials: credentials,
		}
	default:
		resourceType, resource := taskResourceNames(*task)
		event.TaskScheduledEventDetails = &api.TaskScheduledEventDetails{
			ResourceType: new(api.Name(resourceType)), Resource: new(api.Name(resource)),
			Region: new(api.Name(task.Key.Region)), Parameters: new(api.ConnectorParameters(task.Parameters)),
			TaskCredentials: credentials, TimeoutInSeconds: timeout,
		}
		if task.HeartbeatSeconds > 0 {
			event.TaskScheduledEventDetails.HeartbeatInSeconds = new(api.TimeoutInSeconds(task.HeartbeatSeconds))
		}
	}
	return s.taskHistory(tx, execution, revision, frame, task, at, event)
}

func (s *Service) taskStartedHistory(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, task *TaskRecord, at time.Time) error {
	if mapTask(*task) {
		return nil
	}
	event := historyEvent("TaskStarted", task.HistoryID)
	switch task.Kind {
	case "activity":
		event.Type = new(api.HistoryEventType("ActivityStarted"))
		event.ActivityStartedEventDetails = &api.ActivityStartedEventDetails{}
		if task.WorkerName != "" {
			event.ActivityStartedEventDetails.WorkerName = new(api.Identity(task.WorkerName))
		}
	case "lambda":
		event.Type = new(api.HistoryEventType("LambdaFunctionStarted"))
	default:
		resourceType, resource := taskResourceNames(*task)
		event.TaskStartedEventDetails = &api.TaskStartedEventDetails{ResourceType: new(api.Name(resourceType)), Resource: new(api.Name(resource))}
	}
	return s.taskHistory(tx, execution, revision, frame, task, at, event)
}

func (s *Service) taskSubmittedHistory(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, task *TaskRecord, output string, at time.Time) error {
	if mapTask(*task) {
		return nil
	}
	resourceType, resource := taskResourceNames(*task)
	event := historyEvent("TaskSubmitted", task.HistoryID)
	event.TaskSubmittedEventDetails = &api.TaskSubmittedEventDetails{
		ResourceType: new(api.Name(resourceType)), Resource: new(api.Name(resource)),
		Output: new(api.SensitiveData(output)), OutputDetails: historyDataDetails(),
	}
	return s.taskHistory(tx, execution, revision, frame, task, at, event)
}

func (s *Service) taskClosedHistory(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, task *TaskRecord, at time.Time) error {
	if mapTask(*task) {
		return nil
	}
	event := historyEvent("TaskFailed", task.HistoryID)
	resourceType, resource := taskResourceNames(*task)
	var name *api.SensitiveError
	var cause *api.SensitiveCause
	if task.Error != "" {
		name = new(api.SensitiveError(task.Error))
	}
	if task.Cause != "" {
		cause = new(api.SensitiveCause(task.Cause))
	}
	switch task.Kind {
	case "activity":
		switch task.Status {
		case TaskSucceeded:
			event.Type = new(api.HistoryEventType("ActivitySucceeded"))
			event.ActivitySucceededEventDetails = &api.ActivitySucceededEventDetails{Output: new(api.SensitiveData(task.Output)), OutputDetails: historyDataDetails()}
		case TaskTimedOut:
			event.Type = new(api.HistoryEventType("ActivityTimedOut"))
			event.ActivityTimedOutEventDetails = &api.ActivityTimedOutEventDetails{Error: name, Cause: cause}
		default:
			event.Type = new(api.HistoryEventType("ActivityFailed"))
			event.ActivityFailedEventDetails = &api.ActivityFailedEventDetails{Error: name, Cause: cause}
		}
	case "lambda":
		switch task.Status {
		case TaskSucceeded:
			event.Type = new(api.HistoryEventType("LambdaFunctionSucceeded"))
			event.LambdaFunctionSucceededEventDetails = &api.LambdaFunctionSucceededEventDetails{Output: new(api.SensitiveData(task.Output)), OutputDetails: historyDataDetails()}
		case TaskTimedOut:
			event.Type = new(api.HistoryEventType("LambdaFunctionTimedOut"))
			event.LambdaFunctionTimedOutEventDetails = &api.LambdaFunctionTimedOutEventDetails{Error: name, Cause: cause}
		default:
			event.Type = new(api.HistoryEventType("LambdaFunctionFailed"))
			event.LambdaFunctionFailedEventDetails = &api.LambdaFunctionFailedEventDetails{Error: name, Cause: cause}
		}
	default:
		switch task.Status {
		case TaskSucceeded:
			event.Type = new(api.HistoryEventType("TaskSucceeded"))
			event.TaskSucceededEventDetails = &api.TaskSucceededEventDetails{
				ResourceType: new(api.Name(resourceType)), Resource: new(api.Name(resource)),
				Output: new(api.SensitiveData(task.Output)), OutputDetails: historyDataDetails(),
			}
		case TaskTimedOut:
			event.Type = new(api.HistoryEventType("TaskTimedOut"))
			event.TaskTimedOutEventDetails = &api.TaskTimedOutEventDetails{ResourceType: new(api.Name(resourceType)), Resource: new(api.Name(resource)), Error: name, Cause: cause}
		default:
			event.TaskFailedEventDetails = &api.TaskFailedEventDetails{ResourceType: new(api.Name(resourceType)), Resource: new(api.Name(resource)), Error: name, Cause: cause}
		}
	}
	return s.taskHistory(tx, execution, revision, frame, task, at, event)
}
