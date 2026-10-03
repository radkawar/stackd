package stepfunctions

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) registerExecutionOperations() {
	s.registerQueryOperations()
	s.registerTaskOperations()
	register(s, "RedriveExecution", s.redriveExecution)
	s.operations["StartExecution"] = func(ctx context.Context, input any) (any, *awswire.Error) {
		var out *api.StartExecutionOutput
		var effects transitionEffects
		err := s.repository.Attempt(ctx, func(tx Transaction) error {
			effects = transitionEffects{}
			var err error
			out, err = s.startExecution(tx, input.(*api.StartExecutionInput), &effects)
			if err != nil {
				return err
			}
			return s.recordCall(tx.Context(), "StartExecution", input, out, nil)
		})
		if err == nil {
			s.applyEffects(effects)
			s.notify()
		}
		return out, wireError(err)
	}
	s.operations["StartSyncExecution"] = func(ctx context.Context, input any) (any, *awswire.Error) {
		out, err := s.startSyncExecution(ctx, input.(*api.StartSyncExecutionInput))
		return out, wireError(err)
	}
	s.operations["StopExecution"] = func(ctx context.Context, input any) (any, *awswire.Error) {
		var out *api.StopExecutionOutput
		var effects transitionEffects
		err := s.repository.Attempt(ctx, func(tx Transaction) error {
			effects = transitionEffects{}
			var err error
			out, err = s.stopExecution(tx, input.(*api.StopExecutionInput), &effects)
			if err != nil {
				return err
			}
			return s.recordCall(tx.Context(), "StopExecution", input, out, nil)
		})
		if err == nil {
			s.applyEffects(effects)
			s.notify()
		}
		return out, wireError(err)
	}
	s.operations["TestState"] = func(ctx context.Context, input any) (any, *awswire.Error) {
		out, err := s.testState(ctx, input.(*api.TestStateInput))
		return out, wireError(err)
	}
}

func executionInput(in *api.SensitiveData) (string, error) {
	input := "{}"
	if in != nil {
		input = string(*in)
	}
	if len(input) > executionDataLimit {
		return "", invalid("The input exceeds the maximum allowed size of 262144 bytes.")
	}
	if !utf8.ValidString(input) || !json.Valid([]byte(input)) {
		return "", failure("InvalidExecutionInput", "Invalid execution input: input must contain valid JSON.", 400)
	}
	return input, nil
}

func executionName(in *api.Name) (string, error) {
	if in == nil {
		return uuid.NewString(), nil
	}
	name := string(*in)
	if !validResourceName(name) {
		return "", failure("InvalidName", "Invalid Name: '"+name+"'", 400)
	}
	return name, nil
}

func executionTrace(ctx context.Context, in *api.TraceHeader) (string, error) {
	trace := value(in)
	if len(trace) > 256 || strings.IndexFunc(trace, func(r rune) bool { return r > 127 }) >= 0 {
		return "", invalid("traceHeader must be an ASCII string of at most 256 characters.")
	}
	if header := awsctx.FromContext(ctx).TraceHeader; header != "" {
		trace = header
	}
	return trace, nil
}

// admissionRevision resolves the immutable revision exactly once. A published
// current revision does not turn an unqualified admission into a version start.
func admissionRevision(r Reader, machine MachineRecord, qualifier, raw string) (RevisionRecord, string, string, error) {
	revisionID, versionARN, aliasARN := machine.RevisionID, "", ""
	if qualifier != "" {
		number, isVersion := versionNumber(qualifier)
		if !isVersion {
			alias, err := r.Alias(AliasKey{Machine: machine.Key, MachineID: machine.ID, Name: qualifier})
			if errors.Is(err, ErrNotFound) {
				return RevisionRecord{}, "", "", machineMissing(raw)
			}
			if err != nil {
				return RevisionRecord{}, "", "", err
			}
			selection := rand.IntN(100)
			for _, route := range alias.Routes {
				selection -= int(route.Weight)
				if selection < 0 {
					number = route.Version
					break
				}
			}
			if number == 0 {
				return RevisionRecord{}, "", "", errors.New("retained alias has no selected route")
			}
			aliasARN = alias.Key.ARN()
		}
		key := VersionKey{Machine: machine.Key, MachineID: machine.ID, Number: number}
		version, err := r.Version(key)
		if errors.Is(err, ErrNotFound) {
			return RevisionRecord{}, "", "", machineMissing(raw)
		}
		if err != nil {
			return RevisionRecord{}, "", "", err
		}
		revisionID, versionARN = version.RevisionID, key.ARN()
	}
	revision, err := r.Revision(RevisionKey{Scope: machine.Key.Scope, ID: revisionID})
	return revision, versionARN, aliasARN, err
}

func (s *Service) startExecution(tx Transaction, in *api.StartExecutionInput, effects *transitionEffects) (*api.StartExecutionOutput, error) {
	execution, err := s.admitExecution(tx, value(in.StateMachineArn), in.Name, in.Input, in.TraceHeader, false, false, effects)
	if err != nil {
		return nil, err
	}
	return &api.StartExecutionOutput{ExecutionArn: new(api.Arn(execution.Key.ARN)), StartDate: controlTimestamp(execution.Started)}, nil
}

func (s *Service) admitExecution(tx Transaction, raw string, requestedName *api.Name, requestedInput *api.SensitiveData, requestedTrace *api.TraceHeader, synchronous, metadataOnly bool, effects *transitionEffects) (ExecutionRecord, error) {
	action := "StartExecution"
	if synchronous {
		action = "StartSyncExecution"
	}
	if parts := strings.SplitN(raw, ":", 6); len(parts) == 6 && strings.HasPrefix(parts[5], "stateMachine:") && strings.Contains(parts[5], "/") {
		return ExecutionRecord{}, invalid("A Distributed Map state ARN cannot be used to start an execution.")
	}
	machine, qualifier, err := s.controlMachine(tx, raw, action, false, true)
	if err != nil {
		return ExecutionRecord{}, err
	}
	if synchronous && machine.Type != "EXPRESS" {
		return ExecutionRecord{}, unsupportedExecutionType()
	}
	if !synchronous {
		bucket := "StartExecution"
		if machine.Type == "EXPRESS" {
			bucket = "StartExpressExecution"
		}
		quota, _ := workflowQuotaFor(bucket, machine.Key.Region)
		if s.admission.admit(machine.Key.Scope, bucket, s.clock.Now(), quota) != 0 {
			return ExecutionRecord{}, failure("ThrottlingException", "Rate exceeded", 400)
		}
	}
	name, err := executionName(requestedName)
	if err != nil {
		return ExecutionRecord{}, err
	}
	input, err := executionInput(requestedInput)
	if err != nil {
		return ExecutionRecord{}, err
	}
	trace, err := executionTrace(tx.Context(), requestedTrace)
	if err != nil {
		return ExecutionRecord{}, err
	}
	revision, versionARN, aliasARN, err := admissionRevision(tx, machine, qualifier, raw)
	if err != nil {
		return ExecutionRecord{}, err
	}
	working := s.workflowTransaction(tx, revision, revision.RoleARN)
	if synchronous {
		working.reader.fixed, err = s.synchronousMaterial(tx, revision, metadataOnly)
		if err != nil {
			return ExecutionRecord{}, err
		}
	}
	if revision.Encrypted != nil {
		revision, err = working.Revision(revision.Key)
		if err != nil {
			return ExecutionRecord{}, err
		}
	}
	tx = working
	definition, err := s.compiled(revision)
	if err != nil {
		return ExecutionRecord{}, err
	}
	now := s.clock.Now().UTC()
	prefix := "arn:" + machine.Key.Partition + ":states:" + machine.Key.Region + ":" + machine.Key.AccountID + ":"
	arn := prefix + "execution:" + machine.Key.Name + ":" + name
	if machine.Type == "EXPRESS" {
		arn = prefix + "express:" + machine.Key.Name + ":" + name + ":" + uuid.NewString()
	}
	key := ExecutionKey{Scope: machine.Key.Scope, ARN: arn}
	if machine.Type == "STANDARD" {
		previous, err := tx.Execution(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return ExecutionRecord{}, err
		}
		if err == nil {
			retained := previous.MachineID == machine.ID && (previous.Expires == nil || now.Before(*previous.Expires))
			if retained {
				if previous.Status == "RUNNING" && previous.Input == input {
					return previous, nil
				}
				return ExecutionRecord{}, failure("ExecutionAlreadyExists", "Execution Already Exists: '"+arn+"'", 400)
			}
			if err := executionDeletionEffects(tx, key, effects); err != nil {
				return ExecutionRecord{}, err
			}
			if err := tx.DeleteExecution(key); err != nil {
				return ExecutionRecord{}, err
			}
		}
		if err := requireOpenExecutionCapacity(tx, machine.Key.Scope); err != nil {
			return ExecutionRecord{}, err
		}
	}
	timeout := executionTimeout(machine.Type, definition.TimeoutSeconds)
	execution := ExecutionRecord{
		Key: key, Machine: machine.Key, MachineID: machine.ID, RevisionID: revision.Key.ID,
		Name: name, Type: machine.Type, VersionARN: versionARN, AliasARN: aliasARN,
		ParentEventID: apievents.EventID(tx.Context()), TraceHeader: trace,
		Status: "RUNNING", Input: input, Started: now, Deadline: now.Add(timeout), Version: 1, NextFrameID: 1,
	}
	if working.reader.fixed != nil {
		s.encryption.retainSynchronous(key, *working.reader.fixed, execution.Deadline)
	}
	if s.tracing != nil {
		provided := requestedTrace != nil || awsctx.FromContext(tx.Context()).TraceHeader != ""
		tracing, err := s.tracing.BeginTracing(tx.Context(), execution, revision, provided)
		execution.TraceHeader, execution.TraceSegmentID = tracing.Header, tracing.SegmentID
		if err != nil {
			slog.WarnContext(tx.Context(), "Step Functions tracing admission failed", "execution", execution.Key.ARN, "error", err)
		}
	}
	if execution.Type == "EXPRESS" {
		execution.PeakMemoryBytes = executionMemoryBase(revision) + int64(len(input))
	}
	if err := tx.PutExecution(execution); err != nil {
		return ExecutionRecord{}, err
	}
	frame := FrameRecord{Key: FrameKey{Execution: key, ID: 1}, StateName: definition.StartAt, Phase: FrameReady, Input: input, Variables: "{}", Due: &now, Version: 1}
	if err := tx.PutFrame(frame); err != nil {
		return ExecutionRecord{}, err
	}
	event := historyEvent("ExecutionStarted", 0)
	event.ExecutionStartedEventDetails = &api.ExecutionStartedEventDetails{
		Input: new(api.SensitiveData(input)), InputDetails: &api.HistoryEventExecutionDataDetails{Truncated: new(api.Truncated(false))}, RoleArn: new(api.Arn(revision.RoleARN)),
	}
	if versionARN != "" {
		event.ExecutionStartedEventDetails.StateMachineVersionArn = new(api.Arn(versionARN))
	}
	if aliasARN != "" {
		event.ExecutionStartedEventDetails.StateMachineAliasArn = new(api.Arn(aliasARN))
	}
	if _, err := s.appendHistory(tx, &execution, revision, now, HistoryRecord{Event: event}); err != nil {
		return ExecutionRecord{}, err
	}
	if s.events != nil && execution.Type == "STANDARD" {
		if err := s.events.PublishExecutionState(tx.Context(), execution); err != nil {
			return ExecutionRecord{}, err
		}
	}
	if err := s.executionStartedMetrics(tx.Context(), execution); err != nil {
		return ExecutionRecord{}, err
	}
	if err := tx.PutExecution(execution); err != nil {
		return ExecutionRecord{}, err
	}
	return execution, nil
}

func (s *Service) stopExecution(tx Transaction, in *api.StopExecutionInput, effects *transitionEffects) (*api.StopExecutionOutput, error) {
	execution, err := s.publicExecutionFor(tx, value(in.ExecutionArn), "StopExecution")
	if err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(value(in.Error)) > 256 || utf8.RuneCountInString(value(in.Cause)) > 32768 {
		return nil, invalid("error must not exceed 256 characters and cause must not exceed 32768 characters.")
	}
	if execution.Status == "RUNNING" {
		revision, err := tx.Revision(RevisionKey{Scope: execution.Key.Scope, ID: execution.RevisionID})
		if err != nil {
			return nil, err
		}
		if in.Error != nil || in.Cause != nil {
			working := s.workflowTransaction(tx, revision, revision.RoleARN)
			execution, err = working.reader.execution(execution)
			if err != nil {
				return nil, err
			}
			tx = working
		}
		if err := s.endExecution(tx, &execution, revision, "ABORTED", "", value(in.Error), value(in.Cause), s.clock.Now().UTC(), effects); err != nil {
			return nil, err
		}
		execution.Version++
		if err := tx.PutExecution(execution); err != nil {
			return nil, err
		}
	}
	if execution.Stopped == nil {
		return nil, errors.New("terminal execution has no stop time")
	}
	return &api.StopExecutionOutput{StopDate: controlTimestamp(*execution.Stopped)}, nil
}

// Replacement of an expired or old-incarnation ARN cascades through Map Runs.
// Collect every affected attempt before deletion; cancellation runs after commit.
func executionDeletionEffects(r Reader, key ExecutionKey, effects *transitionEffects) error {
	frames, err := r.Frames(key)
	if err != nil {
		return err
	}
	for _, frame := range frames {
		if frame.TaskID != "" {
			effects.cancel = append(effects.cancel, TaskKey{Scope: key.Scope, ID: frame.TaskID})
		}
	}
	runs, err := r.MapRuns(key)
	if err != nil {
		return err
	}
	for _, run := range runs {
		children, err := r.Executions(ExecutionSelection{Scope: key.Scope, MapRunARN: run.Key.ARN})
		if err != nil {
			return err
		}
		for _, child := range children {
			if err := executionDeletionEffects(r, child.Key, effects); err != nil {
				return err
			}
		}
	}
	return nil
}
