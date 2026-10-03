package stepfunctions

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/services/stepfunctions/asl"
)

func (s *Service) startChildren(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, arguments any, at time.Time, effects *transitionEffects) error {
	encoded, err := encodeExecutionData(arguments)
	if err != nil {
		return err
	}
	frame.Arguments, frame.NextItem = encoded, 0
	frame.Error, frame.Cause = "", ""
	frame.ChildGeneration++
	if state.Type == asl.Parallel {
		frame.ItemCount, frame.MaxConcurrency = int64(len(state.Parallel.Branches)), int64(len(state.Parallel.Branches))
		id, err := s.appendHistory(tx, execution, revision, at, frameHistory(frame, historyEvent("ParallelStateStarted", frame.PreviousHistoryID)))
		if err != nil {
			return err
		}
		frame.PreviousHistoryID, frame.Phase = id, FrameJoining
		return s.admitInlineChildren(tx, execution, revision, frame, state, 0, at)
	}
	if state.Map.ItemReader != nil {
		mapEnv := mapInputEnvironment(state, env, arguments)
		if err := mapConcurrency(tx, frame, state, mapEnv); err != nil {
			return err
		}
		event := historyEvent("MapStateStarted", frame.PreviousHistoryID)
		event.MapStateStartedEventDetails = &api.MapStateStartedEventDetails{Length: new(api.UnsignedInteger(0))}
		frame.PreviousHistoryID, err = s.appendHistory(tx, execution, revision, at, frameHistory(frame, event))
		if err != nil {
			return err
		}
		frame.Phase = FrameJoining
		if err := s.createMapRun(tx, execution, revision, frame, state, mapEnv, nil, 0, at); err != nil {
			return err
		}
		return s.startMapReader(tx, execution, revision, frame, state, mapEnv, at)
	}
	items, keys, err := mapSelectedItems(tx.Context(), state, env, arguments)
	if err != nil {
		return err
	}
	itemEnv := mapInputEnvironment(state, env, arguments)
	if err := mapConcurrency(tx, frame, state, itemEnv); err != nil {
		return err
	}
	event := historyEvent("MapStateStarted", frame.PreviousHistoryID)
	event.MapStateStartedEventDetails = &api.MapStateStartedEventDetails{Length: new(api.UnsignedInteger(len(items)))}
	id, err := s.appendHistory(tx, execution, revision, at, frameHistory(frame, event))
	if err != nil {
		return err
	}
	frame.PreviousHistoryID, frame.Phase = id, FrameJoining
	return s.beginMapItems(tx, execution, revision, frame, state, env, arguments, items, keys, nil, "", at, effects)
}

func (s *Service) beginMapItems(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, arguments any, items []any, keys, sources []string, source string, at time.Time, effects *transitionEffects) error {
	itemEnv := mapInputEnvironment(state, env, arguments)
	inputs, err := mapItemInputs(tx.Context(), state, itemEnv, items, keys, sources, source)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(inputs)
	if err != nil {
		return err
	}
	frame.Arguments, frame.ItemCount, frame.NextItem = string(encoded), int64(len(inputs)), 0
	distributed := state.Map.ProcessorConfig.Mode == "DISTRIBUTED"
	if frame.MapRunARN != "" {
		frame.Phase = FrameJoining
		run, err := tx.MapRun(MapRunKey{Scope: execution.Key.Scope, ARN: frame.MapRunARN})
		if err != nil {
			return err
		}
		run.TotalItems = int64(len(items))
		if err := tx.PutMapRun(run); err != nil {
			return err
		}
		childRevision, err := processorRevision(revision, frame, state)
		if err != nil {
			return err
		}
		if err := s.createMapExecutions(tx, execution, childRevision, state, run, inputs, at); err != nil {
			return err
		}
		return s.scheduleMapEffect(tx, execution, revision, frame, "MAP_EXECUTIONS", frame.MapRunARN, "{}", at)
	}
	if distributed {
		if err := s.createMapRun(tx, execution, revision, frame, state, itemEnv, inputs, int64(len(items)), at); err != nil {
			return err
		}
		return s.scheduleMapEffect(tx, execution, revision, frame, "MAP_EXECUTIONS", frame.MapRunARN, "{}", at)
	}
	if frame.ItemCount == 0 {
		return s.completeInlineChildren(tx, execution, revision, frame, state, env, []any{}, at, effects)
	}
	return s.admitInlineChildren(tx, execution, revision, frame, state, 0, at)
}

func mapConcurrency(tx Transaction, frame *FrameRecord, state *asl.State, env asl.Environment) error {
	frame.MaxConcurrency = 40
	if state.Map.ProcessorConfig.Mode == "DISTRIBUTED" {
		frame.MaxConcurrency = 10000
	}
	if state.Map.MaxConcurrency != nil {
		maximum, err := state.Map.MaxConcurrency.Evaluate(tx.Context(), env)
		if err != nil {
			return err
		}
		if maximum != 0 {
			frame.MaxConcurrency = maximum
		}
	}
	return nil
}

func (s *Service) admitInlineChildren(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, running int64, at time.Time) error {
	var items []json.RawMessage
	admissionPrevious := frame.PreviousHistoryID
	if state.Type == asl.Map {
		if err := json.Unmarshal([]byte(frame.Arguments), &items); err != nil {
			return err
		}
	}
	if state.Type == asl.Map && frame.NextItem > 0 {
		event, err := tx.HistoryEvent(execution.Key, admissionPrevious)
		if err != nil {
			return err
		}
		if value(event.Event.Type) == "MapIterationSucceeded" {
			admissionPrevious = int64(*event.Event.PreviousEventId)
		}
	}
	for frame.NextItem < frame.ItemCount && running < frame.MaxConcurrency {
		index := frame.NextItem
		input, path, start, previous := frame.Arguments, "", "", admissionPrevious
		if state.Type == asl.Parallel {
			path, start = branchScope(frame.ScopePath, state.Name, int(index)), state.Parallel.Branches[index].StartAt
		} else {
			input, path, start = string(items[index]), processorScope(frame.ScopePath, state.Name), state.Map.Processor.StartAt
			event := mapIterationEvent("Started", state.Name, index, admissionPrevious)
			var err error
			previous, err = s.appendHistory(tx, execution, revision, at, HistoryRecord{FrameID: execution.NextFrameID + 1, Event: event})
			if err != nil {
				return err
			}
		}
		execution.NextFrameID++
		child := FrameRecord{Key: FrameKey{Execution: execution.Key, ID: execution.NextFrameID}, ParentID: frame.Key.ID, ParentStateID: frame.EnteredHistoryID, ParentAttempt: frame.ChildGeneration, BranchIndex: index, ScopePath: path, StateName: start, Phase: FrameReady, Input: input, Variables: frame.Variables, StartedHistoryID: previous, PreviousHistoryID: previous, Due: new(at), Version: 1}
		if err := tx.PutFrame(child); err != nil {
			return err
		}
		frame.NextItem++
		running++
	}
	return nil
}

func currentChild(parent, child FrameRecord) bool {
	return child.ParentID == parent.Key.ID && child.ParentStateID == parent.EnteredHistoryID && child.ParentAttempt == parent.ChildGeneration
}

func (s *Service) joinChildren(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, at time.Time, effects *transitionEffects) error {
	if frame.MapRunARN != "" {
		return s.joinMapRun(tx, execution, revision, frame, state, env, at, effects)
	}
	children, err := tx.Frames(execution.Key)
	if err != nil {
		return err
	}
	results := make([]any, frame.ItemCount)
	var running, completed int64
	for _, child := range children {
		if !currentChild(*frame, child) {
			continue
		}
		switch child.Phase {
		case FrameComplete:
			if child.BranchIndex < 0 || child.BranchIndex >= frame.ItemCount {
				return fmt.Errorf("invalid retained branch index %d", child.BranchIndex)
			}
			if err := json.Unmarshal([]byte(child.Output), &results[child.BranchIndex]); err != nil {
				return err
			}
			completed++
		case FrameFailed:
			frame.PreviousHistoryID = child.PreviousHistoryID
			return s.failState(tx, execution, revision, frame, state, env, child.Error, child.Cause, at, effects)
		case FrameAborted:
		default:
			running++
		}
	}
	if completed == frame.ItemCount {
		return s.completeInlineChildren(tx, execution, revision, frame, state, env, results, at, effects)
	}
	return s.admitInlineChildren(tx, execution, revision, frame, state, running, at)
}

func (s *Service) completeInlineChildren(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, results []any, at time.Time, effects *transitionEffects) error {
	if _, err := encodeExecutionData(results); err != nil {
		return err
	}
	if _, err := s.appendHistory(tx, execution, revision, at, frameHistory(frame, historyEvent(string(state.Type)+"StateSucceeded", frame.PreviousHistoryID))); err != nil {
		return err
	}
	return s.finishState(tx, execution, revision, frame, state, env, results, state.Next, state.Assign, state.Output, at, effects)
}

func mapIterationEvent(suffix, name string, index, previous int64) api.HistoryEvent {
	event := historyEvent("MapIteration"+suffix, previous)
	details := &api.MapIterationEventDetails{Index: new(api.UnsignedInteger(index)), Name: new(api.Name(name))}
	switch suffix {
	case "Started":
		event.MapIterationStartedEventDetails = details
	case "Succeeded":
		event.MapIterationSucceededEventDetails = details
	case "Failed":
		event.MapIterationFailedEventDetails = details
	case "Aborted":
		event.MapIterationAbortedEventDetails = details
	}
	return event
}

// The caller persists the completed child after this returns. Only wake the
// parent here; joining against the transaction's old child row loses completion.
func (s *Service) childFinished(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, child FrameRecord, at time.Time, effects *transitionEffects) error {
	parent, err := tx.Frame(FrameKey{Execution: execution.Key, ID: child.ParentID})
	if err != nil {
		return err
	}
	if parent.Phase != FrameJoining || !currentChild(parent, child) || execution.Status != "RUNNING" {
		return nil
	}
	previous := child.PreviousHistoryID
	root, err := s.compiled(revision)
	if err != nil {
		return err
	}
	definition, err := definitionScope(root, parent.ScopePath)
	if err != nil {
		return err
	}
	state := definition.States[parent.StateName]
	if child.Phase == FrameComplete && state.Type == asl.Map {
		previous, err = s.appendHistory(tx, execution, revision, at, frameHistory(&child, mapIterationEvent("Succeeded", state.Name, child.BranchIndex, previous)))
		if err != nil {
			return err
		}
	}
	parent.PreviousHistoryID, parent.Due = previous, new(at)
	parent.Version++
	return tx.PutFrame(parent)
}

func processorRevision(revision RevisionRecord, frame *FrameRecord, state *asl.State) (RevisionRecord, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(revision.Definition), &root); err != nil {
		return RevisionRecord{}, err
	}
	var node any = root
	path := processorScope(frame.ScopePath, state.Name)
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch current := node.(type) {
		case map[string]any:
			node = current[part]
			if node == nil && part == "ItemProcessor" {
				node = current["Iterator"]
			}
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(current) {
				return RevisionRecord{}, fmt.Errorf("invalid processor scope %q", path)
			}
			node = current[index]
		default:
			return RevisionRecord{}, fmt.Errorf("missing processor scope %q", path)
		}
	}
	processor, ok := node.(map[string]any)
	if !ok {
		return RevisionRecord{}, fmt.Errorf("missing processor definition %q", path)
	}
	delete(processor, "ProcessorConfig")
	if state.Map.Processor.Language != asl.JSONPath {
		processor["QueryLanguage"] = string(state.Map.Processor.Language)
	}
	encoded, err := json.Marshal(processor)
	if err != nil {
		return RevisionRecord{}, err
	}
	digest := sha256.Sum256([]byte(revision.Key.ID + "\x00" + path))
	child := revision
	child.Key.ID, child.Definition, child.Initial = "map-"+hex.EncodeToString(digest[:]), string(encoded), false
	return child, nil
}

func (s *Service) createMapRun(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, inputs []any, total int64, at time.Time) error {
	label := state.Map.Label
	if label == "" {
		label = uuid.NewString()
	}
	id := uuid.NewString()
	arn := fmt.Sprintf("arn:%s:states:%s:%s:mapRun:%s/%s:%s", execution.Key.Partition, execution.Key.Region, execution.Key.AccountID, execution.Machine.Name, label, id)
	run := MapRunRecord{Key: MapRunKey{Scope: execution.Key.Scope, ARN: arn}, Frame: frame.Key, Label: label, Status: "RUNNING", Started: at, MaxConcurrency: frame.MaxConcurrency, TotalItems: total}
	var err error
	if state.Map.ToleratedFailureCount != nil {
		run.ToleratedFailureCount, err = state.Map.ToleratedFailureCount.Evaluate(tx.Context(), env)
		if err != nil {
			return err
		}
	}
	if state.Map.ToleratedFailurePercentage != nil {
		run.ToleratedFailurePercentage, err = state.Map.ToleratedFailurePercentage.Evaluate(tx.Context(), env)
		if err != nil {
			return err
		}
	}
	childRevision, err := processorRevision(revision, frame, state)
	if err != nil {
		return err
	}
	if _, err := tx.Revision(childRevision.Key); errors.Is(err, ErrNotFound) {
		if err := tx.PutRevision(childRevision); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := tx.PutMapRun(run); err != nil {
		return err
	}
	frame.MapRunARN = arn
	event := historyEvent("MapRunStarted", frame.PreviousHistoryID)
	event.MapRunStartedEventDetails = &api.MapRunStartedEventDetails{MapRunArn: new(api.LongArn(arn))}
	frame.PreviousHistoryID, err = s.appendHistory(tx, execution, revision, at, frameHistory(frame, event))
	if err != nil {
		return err
	}
	return s.createMapExecutions(tx, execution, childRevision, state, run, inputs, at)
}

func (s *Service) createMapExecutions(tx Transaction, execution *ExecutionRecord, childRevision RevisionRecord, state *asl.State, run MapRunRecord, inputs []any, at time.Time) error {
	id := run.Key.ARN[strings.LastIndexByte(run.Key.ARN, ':')+1:]
	for index, input := range inputs {
		encoded, err := encodeExecutionData(input)
		if err != nil {
			return err
		}
		name := fmt.Sprintf("%s_%010d", id, index)
		childARN := fmt.Sprintf("arn:%s:states:%s:%s:execution:%s/%s:%s", execution.Key.Partition, execution.Key.Region, execution.Key.AccountID, execution.Machine.Name, run.Label, name)
		if state.Map.ProcessorConfig.ExecutionType == "EXPRESS" {
			childARN = strings.Replace(childARN, ":execution:", ":express:", 1) + ":" + uuid.NewString()
		}
		child := ExecutionRecord{Key: ExecutionKey{Scope: execution.Key.Scope, ARN: childARN}, Machine: execution.Machine, MachineID: execution.MachineID, RevisionID: childRevision.Key.ID, Name: name, Type: state.Map.ProcessorConfig.ExecutionType, MapRunARN: run.Key.ARN, MapItemCount: mapBatchCardinality(state, input), ParentEventID: execution.ParentEventID, Status: "PENDING", Input: encoded, Started: at, Deadline: execution.Deadline, Version: 1, NextFrameID: 1}
		if err := tx.PutExecution(child); err != nil {
			return err
		}
		childFrame := FrameRecord{Key: FrameKey{Execution: child.Key, ID: 1}, StateName: state.Map.Processor.StartAt, Phase: FrameReady, Input: encoded, Variables: "{}", Version: 1}
		if err := tx.PutFrame(childFrame); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) joinMapRun(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, at time.Time, effects *transitionEffects) error {
	run, err := tx.MapRun(MapRunKey{Scope: execution.Key.Scope, ARN: frame.MapRunARN})
	if err != nil {
		return err
	}
	if run.Status != "RUNNING" {
		return nil
	}
	children, err := tx.Executions(ExecutionSelection{Scope: execution.Key.Scope, MapRunARN: frame.MapRunARN})
	if err != nil {
		return err
	}
	slices.SortFunc(children, func(a, b ExecutionRecord) int { return cmp.Compare(a.Name, b.Name) })
	var running, completed, failed int64
	for _, child := range children {
		switch child.Status {
		case "PENDING", "PENDING_REDRIVE":
		case "RUNNING":
			running++
		case "SUCCEEDED":
			completed++
		default:
			completed++
			failed += child.MapItemCount
		}
	}
	if failureThresholdExceeded(state.Map, failed, run.TotalItems, run.ToleratedFailureCount, run.ToleratedFailurePercentage) {
		for _, child := range children {
			// Express children cannot be canceled. A failed Map Run stops
			// admitting new items but waits for already-running children.
			if child.Type == "EXPRESS" && child.Status == "RUNNING" {
				return nil
			}
		}
		return s.failMapResults(tx, execution, revision, frame, state, env, run, "States.ExceedToleratedFailureThreshold", "The specified tolerated failure threshold was exceeded", at, effects)
	}
	if completed == frame.ItemCount {
		return s.finishMapChildren(tx, execution, revision, frame, state, env, children, at, effects)
	}
	var standardCapacity int64
	capacityRead := false
	for _, child := range children {
		if running >= frame.MaxConcurrency {
			break
		}
		if child.Status != "PENDING" && child.Status != "PENDING_REDRIVE" {
			continue
		}
		if child.Type == "STANDARD" {
			if !capacityRead {
				standardCapacity, err = openExecutionCapacity(tx, child.Key.Scope)
				if err != nil {
					return err
				}
				capacityRead = true
			}
			if standardCapacity <= 0 {
				// Capacity may be released by an unrelated workflow. Retain
				// a service-time retry; this Map's own child completions can
				// wake the join sooner through distributedChildFinished.
				frame.Due = new(at.Add(time.Second))
				break
			}
			standardCapacity--
		}
		childRevision, err := tx.Revision(RevisionKey{Scope: child.Key.Scope, ID: child.RevisionID})
		if err != nil {
			return err
		}
		child.MapGeneration = run.RedriveCount
		if child.Status == "PENDING_REDRIVE" && child.Type == "STANDARD" {
			if err := s.resumeExecution(tx, &child, childRevision, at); err != nil {
				return err
			}
			running++
			continue
		}
		restarting := child.Status == "PENDING_REDRIVE"
		if restarting {
			child.RedriveCount++
			child.Redriven = new(at)
		}
		child.Output, child.Error, child.Cause = "", "", ""
		child.Stopped, child.Expires = nil, nil
		child.Status, child.Started = "RUNNING", at
		maximum := executionTimeout(child.Type, state.Map.Processor.TimeoutSeconds)
		if child.Type == "EXPRESS" {
			child.PeakMemoryBytes = executionMemoryBase(childRevision) + int64(len(child.Input))
		}
		child.Deadline = execution.Deadline
		if deadline := at.Add(maximum); child.Type == "EXPRESS" || deadline.Before(child.Deadline) {
			child.Deadline = deadline
		}
		event := historyEvent("ExecutionStarted", 0)
		event.ExecutionStartedEventDetails = &api.ExecutionStartedEventDetails{Input: new(api.SensitiveData(child.Input)), InputDetails: &api.HistoryEventExecutionDataDetails{Truncated: new(api.Truncated(false))}, RoleArn: new(api.Arn(childRevision.RoleARN))}
		_, err = s.appendHistory(tx, &child, childRevision, at, HistoryRecord{Event: event})
		if err != nil {
			return err
		}
		root, err := tx.Frame(FrameKey{Execution: child.Key, ID: 1})
		if err != nil {
			return err
		}
		if restarting {
			root = FrameRecord{Key: root.Key, StateName: state.Map.Processor.StartAt, Phase: FrameReady, Input: child.Input, Variables: "{}", Version: root.Version}
		}
		root.PreviousHistoryID, root.Due = 0, new(at)
		root.Version++
		if err := tx.PutFrame(root); err != nil {
			return err
		}
		child.Version++
		if err := tx.PutExecution(child); err != nil {
			return err
		}
		if s.events != nil {
			if err := s.events.PublishExecutionState(tx.Context(), child); err != nil {
				return err
			}
		}
		if err := s.executionStartedMetrics(tx.Context(), child); err != nil {
			return err
		}
		frame.NextItem++
		running++
	}
	return nil
}

func (s *Service) distributedChildFinished(tx Transaction, child *ExecutionRecord, at time.Time) error {
	if child.MapRunARN == "" {
		return nil
	}
	run, err := tx.MapRun(MapRunKey{Scope: child.Key.Scope, ARN: child.MapRunARN})
	if err != nil {
		return err
	}
	if run.Status != "RUNNING" {
		return nil
	}
	parent, err := tx.Frame(run.Frame)
	if err != nil {
		return err
	}
	if parent.MapRunARN != run.Key.ARN || parent.Phase != FrameJoining {
		return nil
	}
	parent.Due = new(at)
	parent.Version++
	return tx.PutFrame(parent)
}

// abortDescendants fences the retained attempts as well as cancelling in-flight
// workers after commit. Re-entered/retried parents never touch older children.
func (s *Service) abortDescendants(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, parent *FrameRecord, at time.Time, effects *transitionEffects) error {
	frames, err := tx.Frames(execution.Key)
	if err != nil {
		return err
	}
	slices.SortFunc(frames, func(a, b FrameRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	byID := make(map[int64]FrameRecord, len(frames)+1)
	for _, frame := range frames {
		byID[frame.Key.ID] = frame
	}
	if parent != nil {
		byID[parent.Key.ID] = *parent
	}
	selected := make(map[int64]bool, len(frames))
	if parent == nil {
		for _, frame := range frames {
			selected[frame.Key.ID] = true
		}
	} else {
		for _, frame := range frames {
			owner, ok := byID[frame.ParentID]
			if ok && currentChild(owner, frame) && (frame.ParentID == parent.Key.ID || selected[frame.ParentID]) {
				selected[frame.Key.ID] = true
			}
		}
	}
	previous := execution.NextHistoryID
	if parent != nil {
		previous = parent.PreviousHistoryID
	}
	// Whole-execution cancellation only needs retained control metadata.
	// In particular, a KMS failure must remain terminal with no readable
	// definition or cached compiled state.
	var root *asl.Definition
	if parent != nil {
		root, err = s.compiled(revision)
		if err != nil {
			return err
		}
	}
	for _, frame := range frames {
		if !selected[frame.Key.ID] || frame.Phase == FrameComplete || frame.Phase == FrameAborted || parent == nil && frame.Phase == FrameFailed {
			continue
		}
		if owner, ok := byID[frame.ParentID]; parent != nil && ok && currentChild(owner, frame) {
			definition, err := definitionScope(root, owner.ScopePath)
			if err != nil {
				return err
			}
			state := definition.States[owner.StateName]
			if state.Type == asl.Map && owner.MapRunARN == "" {
				suffix := "Aborted"
				if frame.Phase == FrameFailed {
					suffix = "Failed"
				}
				record := frameHistory(&frame, mapIterationEvent(suffix, owner.StateName, frame.BranchIndex, previous))
				if suffix == "Failed" {
					record.Error, record.Cause = frame.Error, frame.Cause
				}
				if _, err := s.appendHistory(tx, execution, revision, at, record); err != nil {
					return err
				}
			}
		}
		if parent != nil && frame.EnteredHistoryID != 0 {
			definition, err := definitionScope(root, frame.ScopePath)
			if err != nil {
				return err
			}
			state := definition.States[frame.StateName]
			if state.Type == asl.Task || state.Type == asl.Wait || state.Type == asl.Parallel || state.Type == asl.Map {
				if _, err := s.appendHistory(tx, execution, revision, at, frameHistory(&frame, historyEvent(string(state.Type)+"StateAborted", previous))); err != nil {
					return err
				}
			}
		}
		if frame.TaskID != "" {
			task, err := tx.Task(TaskKey{Scope: execution.Key.Scope, ID: frame.TaskID})
			if err != nil {
				return err
			}
			if task.Status == TaskScheduled || task.Status == TaskRunning || task.Status == TaskSubmitted {
				task.Status, task.Deadline = TaskCancelled, nil
				if parent == nil {
					task.HeartbeatDeadline = nil
				}
				task.Version++
				if err := tx.PutTask(task); err != nil {
					return err
				}
				effects.cancel = append(effects.cancel, task.Key)
			}
		}
		frame.Phase, frame.Due = FrameAborted, nil
		frame.Version++
		if err := tx.PutFrame(frame); err != nil {
			return err
		}
	}
	runs, err := tx.MapRuns(execution.Key)
	if err != nil {
		return err
	}
	for _, run := range runs {
		owner, ok := byID[run.Frame.ID]
		if !ok || owner.MapRunARN != run.Key.ARN || parent != nil && run.Frame.ID != parent.Key.ID && !selected[run.Frame.ID] {
			continue
		}
		if run.Status == "RUNNING" {
			run.Status, run.Stopped = "ABORTED", new(at)
			if err := tx.PutMapRun(run); err != nil {
				return err
			}
			if parent != nil {
				if _, err := s.appendHistory(tx, execution, revision, at, frameHistory(&owner, historyEvent("MapRunAborted", previous))); err != nil {
					return err
				}
			}
		}
		if err := s.abortMapExecutions(tx, execution, run, at, effects); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) abortMapExecutions(tx Transaction, execution *ExecutionRecord, run MapRunRecord, at time.Time, effects *transitionEffects) error {
	children, err := tx.Executions(ExecutionSelection{Scope: execution.Key.Scope, MapRunARN: run.Key.ARN})
	if err != nil {
		return err
	}
	for _, child := range children {
		if child.Status == "PENDING_REDRIVE" {
			// Queuing does not replace the prior terminal history. A stopped
			// Map Run withdraws the pending redrive, not that prior outcome.
			last, err := tx.HistoryEvent(child.Key, child.NextHistoryID)
			if err != nil {
				return err
			}
			switch value(last.Event.Type) {
			case "ExecutionFailed":
				child.Status = "FAILED"
			case "ExecutionAborted":
				child.Status = "ABORTED"
			case "ExecutionTimedOut":
				child.Status = "TIMED_OUT"
			default:
				return internalFailure()
			}
			child.Version++
			if err := tx.PutExecution(child); err != nil {
				return err
			}
			continue
		}
		// Never-started inputs remain pending in DescribeMapRun and exports.
		// They have no worker or execution deadline to cancel.
		if child.Status != "RUNNING" || child.Type == "EXPRESS" {
			continue
		}
		childRevision, err := tx.Revision(RevisionKey{Scope: child.Key.Scope, ID: child.RevisionID})
		if err != nil {
			return err
		}
		if err := s.endExecution(tx, &child, childRevision, "ABORTED", "", "", "The parent Map Run was stopped.", at, effects); err != nil {
			return err
		}
		child.Version++
		if err := tx.PutExecution(child); err != nil {
			return err
		}
	}
	return nil
}
