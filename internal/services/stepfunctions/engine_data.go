package stepfunctions

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/services/stepfunctions/asl"
)

const executionDataLimit = 256 * 1024

func continuationContext(ctx context.Context, scope Scope, parentEventID, traceHeader string) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region,
		ParentEventID: parentEventID, TraceHeader: traceHeader,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "states.amazonaws.com", Type: "AWSService"},
	})
}

func evaluationEnvironment(execution ExecutionRecord, revision RevisionRecord, frame FrameRecord, state *asl.State, at time.Time) (asl.Environment, error) {
	var input, original any
	if err := json.Unmarshal([]byte(frame.Input), &input); err != nil {
		return asl.Environment{}, err
	}
	if err := json.Unmarshal([]byte(execution.Input), &original); err != nil {
		return asl.Environment{}, err
	}
	variables := map[string]any{}
	if frame.Variables != "" {
		if err := json.Unmarshal([]byte(frame.Variables), &variables); err != nil {
			return asl.Environment{}, err
		}
	}
	seed := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%d/%d", execution.Key.ARN, frame.Key.ID, frame.EnteredHistoryID, frame.RetryCount)))
	stateContext := map[string]any{"Name": frame.StateName, "EnteredTime": frame.Entered.UTC().Format(time.RFC3339Nano)}
	if state.Type == asl.Task || state.Type == asl.Map || state.Type == asl.Parallel {
		stateContext["RetryCount"] = frame.RetryCount
	}
	executionContext := map[string]any{"Id": execution.Key.ARN, "Input": original, "Name": execution.Name, "RoleArn": revision.RoleARN, "StartTime": execution.Started.UTC().Format(time.RFC3339Nano)}
	if execution.Type == "STANDARD" || execution.MapRunARN != "" {
		executionContext["RedriveCount"] = execution.RedriveCount
		if execution.Type == "STANDARD" && execution.Redriven != nil {
			executionContext["RedriveTime"] = execution.Redriven.UTC().Format(time.RFC3339Nano)
		}
	}
	return asl.Environment{
		Input: input, Variables: variables, Now: at,
		Random: rand.NewChaCha8(seed),
		ContextObject: map[string]any{
			"Execution":    executionContext,
			"StateMachine": map[string]any{"Id": executionMachineARN(execution), "Name": execution.Machine.Name},
			"State":        stateContext,
		},
	}, nil
}

func encodeExecutionData(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", &asl.EvaluationError{Name: "States.Runtime", Cause: "State evaluation did not produce valid JSON: " + err.Error()}
	}
	if len(encoded) > executionDataLimit {
		return "", &asl.EvaluationError{Name: "States.DataLimitExceeded", Cause: "State data exceeds the maximum allowed size of 262144 bytes."}
	}
	return string(encoded), nil
}

func evaluationLocation(err error, location string) error {
	var failure *asl.EvaluationError
	if errors.As(err, &failure) && failure.Location == "" {
		failure.Location = location
	}
	return err
}

func selectedInput(path *asl.Path, env asl.Environment) (any, error) {
	if path == nil {
		return map[string]any{}, nil
	}
	selected, found, err := path.Lookup(env)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, &asl.EvaluationError{Name: "States.Runtime", Cause: "The JSONPath did not identify a value in the state data."}
	}
	return selected, nil
}

// stateArguments applies only the pre-execution half of the shared pipeline.
// The original Environment remains authoritative for JSONata $states.input.
func stateArguments(ctx context.Context, state *asl.State, env asl.Environment, inspect ...stateInspection) (any, error) {
	if state.Language == asl.JSONata {
		if state.Arguments == nil {
			return env.Input, nil
		}
		arguments, err := state.Arguments.Evaluate(ctx, env)
		if err != nil {
			return nil, evaluationLocation(err, "Arguments")
		}
		return arguments, inspectState(inspect, "afterArguments", arguments)
	}
	input, err := selectedInput(state.InputPath, env)
	if err != nil {
		return nil, err
	}
	if err := inspectState(inspect, "afterInputPath", input); err != nil {
		return nil, err
	}
	if state.Parameters == nil {
		if state.Type == asl.Pass || state.Type == asl.Task || state.Type == asl.Parallel {
			return input, inspectState(inspect, "afterParameters", input)
		}
		return input, nil
	}
	env.Input = input
	arguments, err := state.Parameters.Evaluate(ctx, env)
	if err != nil {
		return nil, err
	}
	return arguments, inspectState(inspect, "afterParameters", arguments)
}

// stateOutput keeps Assign and Output on the same entry-variable snapshot. New
// bindings are returned only after both computations have succeeded.
func stateOutput(ctx context.Context, state *asl.State, env asl.Environment, result any, assign, output *asl.Template, inspect ...stateInspection) (string, string, error) {
	assignEnv := env
	if state.Language == asl.JSONPath {
		assignEnv.Input = result
	}
	var final any
	var err error
	if state.Language == asl.JSONata {
		if output == nil {
			final = result
		} else {
			final, err = output.Evaluate(ctx, env)
			err = evaluationLocation(err, "Output")
		}
	} else {
		if state.ResultSelector != nil {
			resultEnv := env
			resultEnv.Input = result
			result, err = state.ResultSelector.Evaluate(ctx, resultEnv)
			if err != nil {
				return "", "", err
			}
		}
		if state.Type == asl.Pass || state.Type == asl.Task || state.Type == asl.Map || state.Type == asl.Parallel {
			if err := inspectState(inspect, "afterResultSelector", result); err != nil {
				return "", "", err
			}
		}
		merged := result
		if state.Type == asl.Task || state.Type == asl.Pass || state.Type == asl.Map || state.Type == asl.Parallel {
			merged = env.Input
			if state.ResultPath != nil {
				merged, err = state.ResultPath.Store(env.Input, result)
				if err != nil {
					return "", "", err
				}
			}
			if err := inspectState(inspect, "afterResultPath", merged); err != nil {
				return "", "", err
			}
		}
		outputEnv := env
		outputEnv.Input = merged
		final, err = selectedInput(state.OutputPath, outputEnv)
	}
	if err != nil {
		return "", "", err
	}
	encoded, err := encodeExecutionData(final)
	if err != nil {
		return "", "", err
	}
	encodedVariables, err := evaluateAssignment(ctx, assign, assignEnv, inspect...)
	return encoded, encodedVariables, err
}

func escapeScopeName(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
}

func processorScope(parent, name string) string {
	return parent + "/States/" + escapeScopeName(name) + "/ItemProcessor"
}

func branchScope(parent, name string, index int) string {
	return parent + "/States/" + escapeScopeName(name) + "/Branches/" + strconv.Itoa(index)
}

func definitionScope(root *asl.Definition, path string) (*asl.Definition, error) {
	if path == "" {
		return root, nil
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for len(parts) > 0 {
		if len(parts) < 3 || parts[0] != "States" {
			return nil, fmt.Errorf("invalid retained ASL scope %q", path)
		}
		name := strings.ReplaceAll(strings.ReplaceAll(parts[1], "~1", "/"), "~0", "~")
		state := root.States[name]
		if state == nil {
			return nil, fmt.Errorf("missing retained ASL scope state %q", name)
		}
		switch parts[2] {
		case "ItemProcessor":
			if state.Map == nil {
				return nil, fmt.Errorf("retained state %q has no item processor", name)
			}
			root, parts = state.Map.Processor, parts[3:]
		case "Branches":
			if len(parts) < 4 || state.Parallel == nil {
				return nil, fmt.Errorf("retained state %q has no branch", name)
			}
			index, err := strconv.Atoi(parts[3])
			if err != nil || index < 0 || index >= len(state.Parallel.Branches) {
				return nil, fmt.Errorf("invalid retained branch index in %q", path)
			}
			root, parts = state.Parallel.Branches[index], parts[4:]
		default:
			return nil, fmt.Errorf("invalid retained ASL scope selector %q", parts[2])
		}
	}
	return root, nil
}
