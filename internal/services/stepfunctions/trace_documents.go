package stepfunctions

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/stepfunctions"
)

// projectTraceHistory consumes committed source events, not the current execution
// status. Delivery may lag behind completion or even a subsequent redrive.
func projectTraceHistory(r Reader, record HistoryRecord, execution ExecutionRecord, revision RevisionRecord) ([]TraceDocument, error) {
	if execution.TraceSegmentID == "" || record.RedriveCount != 0 {
		return nil, nil
	}
	p := workflowTraceProjection{reader: r, execution: execution}
	for field := range strings.SplitSeq(execution.TraceHeader, ";") {
		key, val, _ := strings.Cut(strings.TrimSpace(field), "=")
		switch key {
		case "Root":
			p.traceID = val
		case "Parent":
			p.parentID = val
		}
	}
	kind := value(record.Event.Type)
	switch kind {
	case "ExecutionStarted":
		return []TraceDocument{p.root(revision)}, nil
	case "ExecutionSucceeded", "ExecutionFailed", "ExecutionAborted", "ExecutionTimedOut":
		documents, err := p.terminal(record)
		if err != nil {
			return nil, err
		}
		root := p.root(revision)
		traceFinish(&root, traceEventTime(record), traceFailureCause(record), kind != "ExecutionSucceeded")
		return append(documents, root), nil
	case "ParallelStateFailed", "MapStateFailed":
		return p.failedChildren(record)
	case "ParallelStateStarted":
		frames, err := r.Frames(execution.Key)
		if err != nil {
			return nil, err
		}
		var documents []TraceDocument
		for _, frame := range frames {
			if frame.ParentID != record.FrameID || frame.ParentStateID != record.StateID || frame.StartedHistoryID != traceEventID(record) {
				continue
			}
			container, err := p.container(frame)
			if err != nil {
				return nil, err
			}
			documents = append(documents, container)
		}
		return documents, nil
	case "MapIterationStarted":
		frame, err := p.frame(record.FrameID)
		if err != nil {
			return nil, err
		}
		document, err := p.container(frame)
		if err != nil {
			return nil, err
		}
		return []TraceDocument{document}, nil
	case "MapIterationSucceeded", "MapIterationFailed", "MapIterationAborted":
		frame, err := p.frame(record.FrameID)
		if err != nil {
			return nil, err
		}
		document, err := p.container(frame)
		if err != nil {
			return nil, err
		}
		traceFinish(&document, traceEventTime(record), traceFailureCause(record), kind != "MapIterationSucceeded")
		return []TraceDocument{document}, nil
	}
	if record.Event.StateEnteredEventDetails != nil {
		frame, err := p.frame(record.FrameID)
		if err != nil {
			return nil, err
		}
		state := p.state(record, frame)
		return []TraceDocument{state}, nil
	}
	if record.Event.StateExitedEventDetails != nil || strings.HasSuffix(kind, "StateAborted") {
		entered, err := r.HistoryEvent(execution.Key, record.StateID)
		if err != nil {
			return nil, err
		}
		frame, err := p.frame(entered.FrameID)
		if err != nil {
			return nil, err
		}
		cause, failed, err := p.precedingFailure(record)
		if err != nil {
			return nil, err
		}
		state := p.state(entered, frame)
		traceFinish(&state, traceEventTime(record), cause, failed || strings.HasSuffix(kind, "StateAborted"))
		documents := []TraceDocument{state}
		// A completed frame cannot advance again except on redrive. Match its
		// actual exit identity, never merely its future mutable phase.
		if frame.ParentID != 0 && frame.Phase == FrameComplete && frame.PreviousHistoryID == traceEventID(record) {
			container, err := p.container(frame)
			if err != nil {
				return nil, err
			}
			traceFinish(&container, traceEventTime(record), TraceCause{}, false)
			documents = append(documents, container)
		}
		return documents, nil
	}
	// Attempt failures do not complete a state: a retry shares the same state
	// entry and a later successful attempt has neither fault nor cause.
	return nil, nil
}

type workflowTraceProjection struct {
	reader    Reader
	execution ExecutionRecord
	traceID   string
	parentID  string
}

func (p workflowTraceProjection) root(revision RevisionRecord) TraceDocument {
	return TraceDocument{
		ID: p.execution.TraceSegmentID, Name: revision.Machine.Name,
		StartTime: TraceTimestamp(p.execution.Started), TraceID: p.traceID, ParentID: p.parentID,
		Origin: "AWS::StepFunctions::StateMachine", ResourceARN: revision.Machine.ARN(),
		AWS: map[string]any{"resource_arn": p.execution.Key.ARN}, InProgress: true,
	}
}

func (p workflowTraceProjection) frame(id int64) (FrameRecord, error) {
	// TODO: Comeback capture history-limit tracing before changing rolled-back frame admission; admitted history can lack retained topology.
	return p.reader.Frame(FrameKey{Execution: p.execution.Key, ID: id})
}

func (p workflowTraceProjection) state(entered HistoryRecord, frame FrameRecord) TraceDocument {
	parent := p.execution.TraceSegmentID
	if frame.ParentID != 0 {
		parent = TraceSpanID(parent, "frame", strconv.FormatInt(frame.Key.ID, 10))
	}
	return TraceDocument{
		ID:   TraceSpanID(p.execution.TraceSegmentID, "state", strconv.FormatInt(traceEventID(entered), 10)),
		Name: value(entered.Event.StateEnteredEventDetails.Name), StartTime: traceEventTime(entered),
		TraceID: p.traceID, ParentID: parent, Type: "subsegment", InProgress: true,
	}
}

func (p workflowTraceProjection) container(frame FrameRecord) (TraceDocument, error) {
	origin, err := p.reader.HistoryEvent(p.execution.Key, frame.StartedHistoryID)
	if err != nil {
		return TraceDocument{}, err
	}
	name := ""
	switch value(origin.Event.Type) {
	case "ParallelStateStarted":
		name = "Branch "
	case "MapIterationStarted":
		name = "Iteration "
	default:
		return TraceDocument{}, fmt.Errorf("invalid frame %d trace origin %d", frame.Key.ID, frame.StartedHistoryID)
	}
	return TraceDocument{
		ID:   TraceSpanID(p.execution.TraceSegmentID, "frame", strconv.FormatInt(frame.Key.ID, 10)),
		Name: name + strconv.FormatInt(frame.BranchIndex, 10), StartTime: traceEventTime(origin),
		TraceID: p.traceID, Type: "subsegment", InProgress: true,
		ParentID: TraceSpanID(p.execution.TraceSegmentID, "state", strconv.FormatInt(frame.ParentStateID, 10)),
	}, nil
}

// precedingFailure distinguishes a caught failure from a successful state exit
// with one source read. Compound failures retain their actual Error/Cause beside
// the public history event, which has no modeled failure-details field.
func (p workflowTraceProjection) precedingFailure(record HistoryRecord) (TraceCause, bool, error) {
	if record.Error != "" || record.Cause != "" {
		return traceFailureCause(record), true, nil
	}
	if strings.HasSuffix(value(record.Event.Type), "StateAborted") {
		return TraceCause{}, false, nil
	}
	id := int64(*record.Event.PreviousEventId)
	if id == 0 {
		return TraceCause{}, false, nil
	}
	previous, err := p.reader.HistoryEvent(p.execution.Key, id)
	if err != nil {
		return TraceCause{}, false, err
	}
	return traceFailureCause(previous), traceFailure(previous), nil
}

// failedChildren closes an abandoned compound-state attempt without closing the
// parent state, which may retry. Retained frame topology suffices unless redrive
// has moved a child beyond this event; the original terminal fold handles that
// historical case instead of reading future state as an earlier outcome.
func (p workflowTraceProjection) failedChildren(record HistoryRecord) ([]TraceDocument, error) {
	frames, err := p.reader.Frames(p.execution.Key)
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]FrameRecord, len(frames))
	for _, frame := range frames {
		byID[frame.Key.ID] = frame
	}
	var documents []TraceDocument
	for _, frame := range frames {
		if frame.StartedHistoryID > traceEventID(record) || frame.PreviousHistoryID > traceEventID(record) ||
			!traceDescendant(byID, frame.Key.ID, record.FrameID, record.StateID) {
			continue
		}
		previous, err := p.reader.HistoryEvent(p.execution.Key, frame.PreviousHistoryID)
		if err != nil {
			return nil, err
		}
		end, cause, failed := traceEventTime(record), traceFailureCause(record), true
		if frame.Phase == FrameAborted && frame.Error == "" && frame.Cause == "" {
			cause = TraceCause{}
		}
		if frame.Phase == FrameComplete {
			end, cause, failed = traceEventTime(previous), TraceCause{}, false
		}
		if frame.EnteredHistoryID != 0 && (previous.StateID != frame.EnteredHistoryID || previous.Event.StateExitedEventDetails == nil) {
			entered, err := p.reader.HistoryEvent(p.execution.Key, frame.EnteredHistoryID)
			if err != nil {
				return nil, err
			}
			state := p.state(entered, frame)
			stateEnd, stateCause := end, cause
			if traceFailure(previous) && previous.StateID == frame.EnteredHistoryID {
				stateEnd, stateCause = traceEventTime(previous), traceFailureCause(previous)
			} else if value(entered.Event.Type) == "FailStateEntered" {
				stateEnd = traceEventTime(entered)
			}
			traceFinish(&state, stateEnd, stateCause, failed)
			documents = append(documents, state)
		}
		container, err := p.container(frame)
		if err != nil {
			return nil, err
		}
		traceFinish(&container, end, cause, failed)
		documents = append(documents, container)
	}
	return documents, nil
}

// terminal folds history once, at the original execution boundary only. This
// closes states with no StateExited event (Fail, exhausted attempts, cancellation
// and timeout), including when mutable frames have already been redriven. No
// retained span registry or second publication cursor is needed.
func (p workflowTraceProjection) terminal(terminal HistoryRecord) ([]TraceDocument, error) {
	history, err := p.reader.History(p.execution.Key)
	if err != nil {
		return nil, err
	}
	frames, err := p.reader.Frames(p.execution.Key)
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]FrameRecord, len(frames))
	starts := make(map[int64][]int64)
	for _, frame := range frames {
		byID[frame.Key.ID] = frame
		if frame.ParentID != 0 {
			starts[frame.StartedHistoryID] = append(starts[frame.StartedHistoryID], frame.Key.ID)
		}
	}
	type openState struct {
		entered HistoryRecord
		failure HistoryRecord
	}
	type openFrame struct {
		last HistoryRecord
	}
	active := make(map[int64]openState)
	containers := make(map[int64]*openFrame)
	var documents []TraceDocument
	closeContainer := func(id int64, at HistoryRecord, cause TraceCause, fault bool) error {
		if containers[id] == nil {
			return nil
		}
		document, err := p.container(byID[id])
		if err != nil {
			return err
		}
		traceFinish(&document, traceEventTime(at), cause, fault)
		documents = append(documents, document)
		delete(containers, id)
		return nil
	}
	closeState := func(id int64, at HistoryRecord, fallback TraceCause, fault bool) error {
		state, ok := active[id]
		if !ok {
			return nil
		}
		frame, ok := byID[state.entered.FrameID]
		if !ok {
			return fmt.Errorf("missing frame %d for trace state %d", state.entered.FrameID, id)
		}
		cause, end := fallback, traceEventTime(at)
		if state.failure.Event.Id != nil && traceFailure(at) && value(at.Event.Type) != "ExecutionTimedOut" {
			failureCause := traceFailureCause(state.failure)
			if fallback.Message == failureCause.Message && slices.Equal(fallback.Exceptions, failureCause.Exceptions) {
				cause, end, fault = failureCause, traceEventTime(state.failure), true
			}
		}
		if value(state.entered.Event.Type) == "FailStateEntered" {
			end = traceEventTime(state.entered)
		}
		document := p.state(state.entered, frame)
		traceFinish(&document, end, cause, fault)
		documents = append(documents, document)
		delete(active, id)
		return nil
	}
	closeDescendants := func(owner HistoryRecord, failed bool) error {
		cause := traceFailureCause(owner)
		for id, state := range active {
			if traceDescendant(byID, state.entered.FrameID, owner.FrameID, owner.StateID) {
				if err := closeState(id, owner, cause, failed); err != nil {
					return err
				}
			}
		}
		for id, frame := range containers {
			if !traceDescendant(byID, id, owner.FrameID, owner.StateID) {
				continue
			}
			end := owner
			if !failed && frame.last.Event.StateExitedEventDetails != nil {
				end = frame.last
			}
			if err := closeContainer(id, end, cause, failed); err != nil {
				return err
			}
		}
		return nil
	}
	for _, record := range history {
		if traceEventID(record) >= traceEventID(terminal) || record.RedriveCount != 0 {
			break
		}
		kind := value(record.Event.Type)
		if record.Event.StateEnteredEventDetails != nil {
			active[record.StateID] = openState{entered: record}
		}
		frame := byID[record.FrameID]
		for _, id := range starts[traceEventID(record)] {
			containers[id] = &openFrame{}
		}
		if container := containers[record.FrameID]; container != nil {
			container.last = record
		}
		if state, ok := active[record.StateID]; ok {
			if traceFailure(record) && kind != "MapIterationFailed" {
				state.failure = record
				active[record.StateID] = state
			} else {
				switch kind {
				case "TaskScheduled", "ActivityScheduled", "LambdaFunctionScheduled", "ParallelStateStarted", "MapStateStarted":
					state.failure = HistoryRecord{}
					active[record.StateID] = state
				}
			}
		}
		if record.Event.StateExitedEventDetails != nil {
			delete(active, record.StateID)
			if container := containers[record.FrameID]; container != nil && frame.Phase == FrameComplete && frame.PreviousHistoryID == traceEventID(record) {
				if err := closeContainer(record.FrameID, record, TraceCause{}, false); err != nil {
					return nil, err
				}
			}
		}
		switch kind {
		case "ParallelStateSucceeded", "MapStateSucceeded":
			if err := closeDescendants(record, false); err != nil {
				return nil, err
			}
		case "ParallelStateFailed", "MapStateFailed":
			if err := closeDescendants(record, true); err != nil {
				return nil, err
			}
		case "MapIterationSucceeded", "MapIterationFailed", "MapIterationAborted":
			if err := closeContainer(record.FrameID, record, traceFailureCause(record), kind != "MapIterationSucceeded"); err != nil {
				return nil, err
			}
		default:
			if strings.HasSuffix(kind, "StateAborted") {
				if err := closeState(record.StateID, record, traceFailureCause(record), true); err != nil {
					return nil, err
				}
				if err := closeContainer(record.FrameID, record, traceFailureCause(record), true); err != nil {
					return nil, err
				}
			}
		}
	}
	cause := traceFailureCause(terminal)
	failed := value(terminal.Event.Type) != "ExecutionSucceeded"
	for id := range active {
		if err := closeState(id, terminal, cause, failed); err != nil {
			return nil, err
		}
	}
	for id := range containers {
		if err := closeContainer(id, terminal, cause, failed); err != nil {
			return nil, err
		}
	}
	return documents, nil
}

func traceDescendant(frames map[int64]FrameRecord, id, owner, stateID int64) bool {
	for id != 0 {
		frame, ok := frames[id]
		if !ok || frame.ParentID == 0 {
			return false
		}
		if frame.ParentID == owner {
			return frame.ParentStateID == stateID
		}
		id = frame.ParentID
	}
	return false
}

func traceFailureCause(record HistoryRecord) TraceCause {
	if record.Error != "" || record.Cause != "" {
		return TraceCause{Message: record.Cause, Exceptions: []TraceException{{Message: record.Cause, Type: record.Error}}}
	}
	event := record.Event
	var name *api.SensitiveError
	var cause *api.SensitiveCause
	switch {
	case event.ExecutionFailedEventDetails != nil:
		name, cause = event.ExecutionFailedEventDetails.Error, event.ExecutionFailedEventDetails.Cause
	case event.ExecutionAbortedEventDetails != nil:
		name, cause = event.ExecutionAbortedEventDetails.Error, event.ExecutionAbortedEventDetails.Cause
	case event.ExecutionTimedOutEventDetails != nil:
		name, cause = event.ExecutionTimedOutEventDetails.Error, event.ExecutionTimedOutEventDetails.Cause
	case event.ActivityFailedEventDetails != nil:
		name, cause = event.ActivityFailedEventDetails.Error, event.ActivityFailedEventDetails.Cause
	case event.ActivityTimedOutEventDetails != nil:
		name, cause = event.ActivityTimedOutEventDetails.Error, event.ActivityTimedOutEventDetails.Cause
	case event.ActivityScheduleFailedEventDetails != nil:
		name, cause = event.ActivityScheduleFailedEventDetails.Error, event.ActivityScheduleFailedEventDetails.Cause
	case event.LambdaFunctionFailedEventDetails != nil:
		name, cause = event.LambdaFunctionFailedEventDetails.Error, event.LambdaFunctionFailedEventDetails.Cause
	case event.LambdaFunctionTimedOutEventDetails != nil:
		name, cause = event.LambdaFunctionTimedOutEventDetails.Error, event.LambdaFunctionTimedOutEventDetails.Cause
	case event.LambdaFunctionScheduleFailedEventDetails != nil:
		name, cause = event.LambdaFunctionScheduleFailedEventDetails.Error, event.LambdaFunctionScheduleFailedEventDetails.Cause
	case event.LambdaFunctionStartFailedEventDetails != nil:
		name, cause = event.LambdaFunctionStartFailedEventDetails.Error, event.LambdaFunctionStartFailedEventDetails.Cause
	case event.TaskFailedEventDetails != nil:
		name, cause = event.TaskFailedEventDetails.Error, event.TaskFailedEventDetails.Cause
	case event.TaskTimedOutEventDetails != nil:
		name, cause = event.TaskTimedOutEventDetails.Error, event.TaskTimedOutEventDetails.Cause
	case event.TaskStartFailedEventDetails != nil:
		name, cause = event.TaskStartFailedEventDetails.Error, event.TaskStartFailedEventDetails.Cause
	case event.TaskSubmitFailedEventDetails != nil:
		name, cause = event.TaskSubmitFailedEventDetails.Error, event.TaskSubmitFailedEventDetails.Cause
	case event.EvaluationFailedEventDetails != nil:
		name, cause = event.EvaluationFailedEventDetails.Error, event.EvaluationFailedEventDetails.Cause
	case event.MapRunFailedEventDetails != nil:
		name, cause = event.MapRunFailedEventDetails.Error, event.MapRunFailedEventDetails.Cause
	}
	if name == nil && cause == nil {
		return TraceCause{}
	}
	return TraceCause{Message: value(cause), Exceptions: []TraceException{{Message: value(cause), Type: value(name)}}}
}

func traceFailure(record HistoryRecord) bool {
	kind := value(record.Event.Type)
	return strings.HasSuffix(kind, "Failed") || strings.HasSuffix(kind, "TimedOut")
}

func traceFinish(document *TraceDocument, end float64, cause TraceCause, fault bool) {
	document.InProgress = false
	document.EndTime = new(end)
	document.Cause, document.Fault = cause, fault
}

func traceEventID(record HistoryRecord) int64 { return int64(*record.Event.Id) }

func traceEventTime(record HistoryRecord) float64 {
	return TraceTimestamp(time.Time(*record.Event.Timestamp))
}
