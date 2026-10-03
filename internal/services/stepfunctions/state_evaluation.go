package stepfunctions

import (
	"context"
	"time"

	"stackd/internal/services/stepfunctions/asl"
)

// Inspection observes completed dataflow stages, never reevaluates an expression
// (intrinsics may be random). History captures only newly assigned bindings.
type stateInspection func(stage string, value any) error

func inspectState(observers []stateInspection, stage string, value any) error {
	for _, inspect := range observers {
		if inspect != nil {
			if err := inspect(stage, value); err != nil {
				return err
			}
		}
	}
	return nil
}

type stateEvaluation struct {
	Arguments any
	Result    any
	Next      string
	Assign    *asl.Template
	Output    *asl.Template
	Due       *time.Time
	Failure   *asl.EvaluationError
}

// evaluateState is the pre-completion semantics shared by the retained kernel
// and TestState. Task effects, branch ownership and durable waits remain outside
// this evaluator; each consumer uses the same compiled dataflow and task adapter.
func evaluateState(ctx context.Context, state *asl.State, env asl.Environment, at time.Time, inspect stateInspection) (stateEvaluation, error) {
	out := stateEvaluation{Next: state.Next, Assign: state.Assign, Output: state.Output}
	if state.Type == asl.Pass && state.Pass.HasResult && state.Pass.Result != nil {
		out.Result = state.Pass.Result
		if err := inspectState([]stateInspection{inspect}, "result", out.Result); err != nil {
			return out, err
		}
		return out, nil
	}
	var err error
	if state.Type == asl.Fail {
		out.Arguments = env.Input
		if state.Language == asl.JSONPath {
			if err := inspectState([]stateInspection{inspect}, "afterInputPath", env.Input); err != nil {
				return out, err
			}
		}
	} else {
		out.Arguments, err = stateArguments(ctx, state, env, inspect)
		if err != nil {
			return out, err
		}
	}
	out.Result = out.Arguments
	switch state.Type {
	case asl.Succeed:
		out.Next, out.Assign = "", nil
	case asl.Choice:
		choiceEnv := env
		if state.Language == asl.JSONPath {
			choiceEnv.Input = out.Arguments
		}
		rule, err := asl.SelectChoice(ctx, state, choiceEnv)
		if err != nil {
			return out, err
		}
		out.Next, out.Assign, out.Output = rule.Next, rule.Assign, rule.Output
	case asl.Wait:
		waitEnv := env
		if state.Language == asl.JSONPath {
			waitEnv.Input = out.Arguments
		}
		due := at
		if state.Wait.Seconds != nil {
			seconds, err := state.Wait.Seconds.Evaluate(ctx, waitEnv)
			if err != nil {
				return out, err
			}
			due = at.Add(time.Duration(seconds) * time.Second)
		} else {
			text, err := state.Wait.Timestamp.Evaluate(ctx, waitEnv)
			if err != nil {
				return out, err
			}
			due, err = time.Parse(time.RFC3339Nano, text)
			if err != nil {
				return out, &asl.EvaluationError{Name: "States.Runtime", Cause: "The Wait timestamp is invalid."}
			}
			due = due.Truncate(time.Second)
			if due.Before(at) {
				due = at
			}
		}
		out.Due = &due
	case asl.Fail:
		failure := &asl.EvaluationError{}
		if state.Fail.Error != nil {
			failure.Name, err = state.Fail.Error.Evaluate(ctx, env)
			if err != nil {
				return out, err
			}
		}
		if state.Fail.Cause != nil {
			failure.Cause, err = state.Fail.Cause.Evaluate(ctx, env)
			if err != nil {
				return out, err
			}
		}
		out.Failure = failure
	}
	return out, nil
}

// evaluateCatch shares error dataflow and assignment with retained transitions.
// Selection of the first matching handler belongs to each caller's retry counts.
func evaluateCatch(ctx context.Context, state *asl.State, env asl.Environment, catcher asl.Catcher, name, cause string, inspect stateInspection) (string, string, error) {
	failure := map[string]any{"Error": name, "Cause": cause}
	catchEnv := env
	catchEnv.ErrorOutput = failure
	var output any = failure
	if state.Language == asl.JSONPath {
		catchEnv.Input = failure
		output = env.Input
		if catcher.ResultPath != nil {
			var err error
			output, err = catcher.ResultPath.Store(env.Input, failure)
			if err != nil {
				return "", "", err
			}
		}
		if err := inspectState([]stateInspection{inspect}, "afterResultPath", output); err != nil {
			return "", "", err
		}
	} else if catcher.Output != nil {
		var err error
		output, err = catcher.Output.Evaluate(ctx, catchEnv)
		if err != nil {
			return "", "", err
		}
	}
	encoded, err := encodeExecutionData(output)
	if err != nil {
		return "", "", err
	}
	variables, err := evaluateAssignment(ctx, catcher.Assign, catchEnv, inspect)
	return encoded, variables, err
}

func failureThresholdExceeded(state *asl.MapState, failed, total, count int64, percentage float64) bool {
	countExceeded := failed > count && (state.ToleratedFailureCount != nil || state.ToleratedFailurePercentage == nil)
	percentageExceeded := state.ToleratedFailurePercentage != nil && total > 0 && float64(failed)*100 > percentage*float64(total)
	return countExceeded || percentageExceeded
}
