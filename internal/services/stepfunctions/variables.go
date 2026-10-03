package stepfunctions

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"

	"stackd/internal/services/stepfunctions/asl"
)

const executionVariableLimit = 10 * 1024 * 1024

// Assign quotas count serialized values, not object keys or separators. The
// same encodings feed history and inspection; accumulated scopes are not an
// execution input/output payload and may exceed 256 KiB.
func evaluateAssignment(ctx context.Context, assign *asl.Template, env asl.Environment, inspect ...stateInspection) (string, error) {
	if assign == nil {
		return "", nil
	}
	assigned, err := assign.Evaluate(ctx, env)
	if err != nil {
		return "", evaluationLocation(err, "Assign")
	}
	bindings, ok := assigned.(map[string]any)
	if !ok {
		return "", &asl.EvaluationError{Name: "States.QueryEvaluationError", Cause: "Assign must evaluate to an object.", Location: "Assign"}
	}
	encoded := make(map[string]json.RawMessage, len(bindings))
	size := 0
	for name, value := range bindings {
		data, err := json.Marshal(value)
		if err != nil {
			return "", &asl.EvaluationError{Name: "States.QueryEvaluationError", Cause: err.Error(), Location: "Assign"}
		}
		encoded[name] = data
		size += len(data)
	}
	if size > executionDataLimit {
		return "", &asl.EvaluationError{Name: "States.DataLimitExceeded", Cause: fmt.Sprintf("The Assign field exceeds the maximum variable assignment size by %d bytes.", size-executionDataLimit), Location: "Assign"}
	}
	variables := maps.Clone(env.Variables)
	for name, data := range encoded {
		variables[name] = data
	}
	if err := inspectState(inspect, "variables", encoded); err != nil {
		return "", err
	}
	data, err := json.Marshal(variables)
	return string(data), err
}

// applyFrameVariables counts live workflow-local scopes once. Child frames
// retain an inherited snapshot, but inherited values are owned by the parent;
// completed branches and iterations have already left scope.
func applyFrameVariables(r Reader, frame *FrameRecord, encoded string) error {
	if encoded == "" {
		return nil
	}
	frames, err := r.Frames(frame.Key.Execution)
	if err != nil {
		return err
	}
	byID := make(map[int64]FrameRecord, len(frames))
	for _, item := range frames {
		byID[item.Key.ID] = item
	}
	current := *frame
	current.Variables = encoded
	byID[current.Key.ID] = current
	sizes := make(map[int64]map[string]int)
	valueSizes := func(id int64) (map[string]int, error) {
		if cached, ok := sizes[id]; ok {
			return cached, nil
		}
		var values map[string]json.RawMessage
		if err := json.Unmarshal([]byte(byID[id].Variables), &values); err != nil {
			return nil, err
		}
		lengths := make(map[string]int, len(values))
		for name, value := range values {
			lengths[name] = len(value)
		}
		sizes[id] = lengths
		return lengths, nil
	}
	total := 0
	for id, item := range byID {
		if item.Phase == FrameComplete || item.Phase == FrameFailed || item.Phase == FrameAborted {
			continue
		}
		values, err := valueSizes(id)
		if err != nil {
			return err
		}
		var inherited map[string]int
		if item.ParentID != 0 {
			inherited, err = valueSizes(item.ParentID)
			if err != nil {
				return err
			}
		}
		for name, size := range values {
			if _, outer := inherited[name]; !outer {
				total += size
			}
		}
	}
	if total > executionVariableLimit {
		return &asl.EvaluationError{Name: "States.DataLimitExceeded", Cause: fmt.Sprintf("Execution total variable size limit exceeded. State '%s' assigned variables that exceed the total execution limit by %d bytes.", frame.StateName, total-executionVariableLimit), Location: "Assign"}
	}
	frame.Variables = encoded
	return nil
}
