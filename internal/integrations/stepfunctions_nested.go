package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awscatalog"
	"stackd/internal/services/stepfunctions"
)

func (t *StepFunctionsTasks) runNestedTask(ctx context.Context, task stepfunctions.TaskRecord, revision stepfunctions.RevisionRecord, submit func(stepfunctions.TaskOutcome) error) (stepfunctions.TaskOutcome, error) {
	sync := task.Kind == "sync"
	if (sync || task.Kind == "callback") && submit == nil {
		return stepfunctions.TaskOutcome{}, errors.New("nested task has no submission sink")
	}
	var accepted struct{ ExecutionArn string }
	if task.Output != "" {
		if err := json.Unmarshal([]byte(task.Output), &accepted); err != nil {
			return stepfunctions.TaskOutcome{}, err
		}
		if accepted.ExecutionArn == "" {
			return stepfunctions.TaskOutcome{}, errors.New("retained nested submission has no execution ARN")
		}
	}
	childARN := accepted.ExecutionArn
	var completion <-chan struct{}
	if sync && childARN != "" {
		parts := strings.SplitN(childARN, ":", 6)
		if len(parts) == 6 && parts[4] == task.Key.Scope.AccountID {
			var unsubscribe func()
			completion, unsubscribe = t.subscribeExecution(childARN)
			defer unsubscribe()
		}
	}
	// The retained ARN is the recovery fence: never call StartExecution again
	// after the source committed the actual destination's submission response.
	if childARN == "" {
		parameters, err := stepFunctionsJSONObject(task.Parameters)
		if err != nil {
			return stepfunctions.TaskOutcome{Error: "States.Runtime", Cause: err.Error()}, nil
		}
		if sync {
			var machineARN, name string
			_ = json.Unmarshal(parameters["StateMachineArn"], &machineARN)
			parts := strings.SplitN(machineARN, ":", 8)
			if len(parts) >= 7 && parts[2] == "states" && parts[4] == task.Key.Scope.AccountID && parts[5] == "stateMachine" {
				if _, present := parameters["Name"]; !present {
					name = uuid.NewString()
					parameters["Name"], _ = json.Marshal(name)
				} else {
					_ = json.Unmarshal(parameters["Name"], &name)
				}
				if name != "" {
					// Pick the ordinary generated execution name before starting,
					// so even an immediate child cannot outrun its exact subscriber.
					arn := strings.Join(parts[:5], ":") + ":execution:" + parts[6] + ":" + name
					var unsubscribe func()
					completion, unsubscribe = t.subscribeExecution(arn)
					defer unsubscribe()
				}
			}
		}
		if input, present := parameters["Input"]; present {
			parameters["Input"] = stepFunctionsJSONString(input)
		}
		input, err := json.Marshal(parameters)
		if err != nil {
			return stepfunctions.TaskOutcome{}, err
		}
		result, wire := t.Commands.CallResponse(ctx, "stepfunctions", "StartExecution", input)
		if wire != nil {
			return stepFunctionsCommandFailure(result, wire, true), nil
		}
		response, ok := result.Output.(*api.StartExecutionOutput)
		if !ok || response == nil || response.ExecutionArn == nil {
			return stepfunctions.TaskOutcome{}, fmt.Errorf("StartExecution returned %T without an execution ARN", result.Output)
		}
		childARN = string(*response.ExecutionArn)
		output, err := stepFunctionsNestedOutput(result, false)
		if err != nil {
			return stepfunctions.TaskOutcome{}, err
		}
		outcome := stepfunctions.TaskOutcome{Output: string(output), Submitted: sync || task.Kind == "callback"}
		if outcome.Submitted {
			if err := submit(outcome); err != nil {
				if sync && !errors.Is(context.Cause(ctx), stepfunctions.ErrTaskInterrupted) {
					t.stopNestedTask(ctx, task, revision, childARN)
				}
				return stepfunctions.TaskOutcome{}, err
			}
		}
		if !sync {
			return outcome, nil
		}
	}
	if !sync {
		return stepfunctions.TaskOutcome{}, errors.New("only synchronous tasks can resume a retained child execution")
	}
	defer func() {
		if ctx.Err() != nil && !errors.Is(context.Cause(ctx), stepfunctions.ErrTaskInterrupted) {
			t.stopNestedTask(ctx, task, revision, childARN)
		}
	}()
	result, failure, err := t.waitNestedTask(ctx, task, revision, childARN, completion)
	if err != nil || failure.Error != "" {
		return failure, err
	}
	response, ok := result.Output.(*api.DescribeExecutionOutput)
	if !ok || response == nil || response.Status == nil {
		return stepfunctions.TaskOutcome{}, fmt.Errorf("DescribeExecution returned %T without a status", result.Output)
	}
	output, err := stepFunctionsNestedOutput(result, strings.HasSuffix(task.Resource, ".sync:2"))
	if err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	if *response.Status != "SUCCEEDED" {
		return stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: string(output)}, nil
	}
	return stepfunctions.TaskOutcome{Output: string(output)}, nil
}

func (t *StepFunctionsTasks) waitNestedTask(ctx context.Context, task stepfunctions.TaskRecord, revision stepfunctions.RevisionRecord, childARN string, completion <-chan struct{}) (StepFunctionsCommandResult, stepfunctions.TaskOutcome, error) {
	parameters, err := json.Marshal(map[string]string{"ExecutionArn": childARN})
	if err != nil {
		return StepFunctionsCommandResult{}, stepfunctions.TaskOutcome{}, err
	}
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	scoped, renewAt := ctx, time.Now().Add(30*time.Minute)
	// Recovered attempts subscribe before reconciling their retained child.
	// Fresh same-account tasks prefer delivered events; polling repairs a
	// missed event only through the actual DescribeExecution IAM boundary.
	reconcile := task.Output != "" || completion == nil
	for {
		if !reconcile {
			select {
			case <-ctx.Done():
				return StepFunctionsCommandResult{}, stepfunctions.TaskOutcome{}, ctx.Err()
			case <-completion:
				return t.completedNestedTask(ctx, childARN)
			case <-poll.C:
			}
		}
		reconcile = false
		// Do not turn a delivered event into a new polling permission check.
		select {
		case <-completion:
			return t.completedNestedTask(ctx, childARN)
		default:
		}
		if !time.Now().Before(renewAt) {
			// Renew long-running observations without a per-task credential cache.
			var failure stepfunctions.TaskOutcome
			var renewed context.Context
			renewed, failure, err = t.taskContext(ctx, task, revision)
			if err != nil || failure.Error != "" {
				if completion == nil {
					return StepFunctionsCommandResult{}, failure, err
				}
			} else {
				scoped = renewed
			}
			renewAt = time.Now().Add(30 * time.Minute)
		}
		result, wire := t.Commands.Call(scoped, "stepfunctions", "DescribeExecution", parameters)
		if wire != nil {
			if completion != nil && (wire.Code == "AccessDenied" || wire.Code == "AccessDeniedException") {
				// Native executions still complete through the admitted managed
				// consumer after both EventBridge and polling grants are removed.
				continue
			}
			return result, stepFunctionsCommandFailure(result, wire, true), nil
		}
		response, ok := result.Output.(*api.DescribeExecutionOutput)
		if !ok || response == nil || response.Status == nil {
			return result, stepfunctions.TaskOutcome{}, fmt.Errorf("DescribeExecution returned %T without a status", result.Output)
		}
		if *response.Status != "RUNNING" && *response.Status != "PENDING_REDRIVE" {
			return result, stepfunctions.TaskOutcome{}, nil
		}
	}
}

func (t *StepFunctionsTasks) completedNestedTask(ctx context.Context, childARN string) (StepFunctionsCommandResult, stepfunctions.TaskOutcome, error) {
	// This trusted projection is reachable only after the real reserved target
	// delivered a matching terminal event. It is not an event substitute.
	if t.Executions == nil {
		return StepFunctionsCommandResult{}, stepfunctions.TaskOutcome{}, errors.New("retained Step Functions execution observer is not configured")
	}
	output, err := t.Executions.WaitExecution(ctx, childARN)
	if err != nil {
		return StepFunctionsCommandResult{}, stepfunctions.TaskOutcome{}, err
	}
	service, ok := awscatalog.LookupService("stepfunctions")
	if !ok {
		return StepFunctionsCommandResult{}, stepfunctions.TaskOutcome{}, errors.New("step functions model is unavailable")
	}
	operation, ok := service.Operation("DescribeExecution")
	if !ok {
		return StepFunctionsCommandResult{}, stepfunctions.TaskOutcome{}, errors.New("DescribeExecution model is unavailable")
	}
	return StepFunctionsCommandResult{Service: service, Operation: operation, Output: output}, stepfunctions.TaskOutcome{}, nil
}

func (t *StepFunctionsTasks) stopNestedTask(ctx context.Context, task stepfunctions.TaskRecord, revision stepfunctions.RevisionRecord, childARN string) {
	// Best effort does not mean privileged: renew the real target role and let
	// StopExecution perform the same IAM checks as a direct caller. Detaching
	// cancellation only gives the abort command a bounded opportunity to run.
	completion, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	scoped, failure, err := t.taskContext(completion, task, revision)
	if err != nil || failure.Error != "" {
		return
	}
	parameters, err := json.Marshal(map[string]string{"ExecutionArn": childARN, "Error": "States.TaskFailed", "Cause": "The parent task was cancelled."})
	if err != nil {
		return
	}
	_, _ = t.Commands.Call(scoped, "stepfunctions", "StopExecution", parameters)
}

func stepFunctionsNestedOutput(result StepFunctionsCommandResult, objects bool) ([]byte, error) {
	encoded, err := awsapi.EncodeSDKOutput(result.Service, result.Operation, result.Output)
	if err != nil {
		return nil, err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, err
	}
	if document == nil {
		return nil, errors.New("nested execution returned no response document")
	}
	setDate := func(name string, date *time.Time) {
		if date != nil {
			document[name] = json.RawMessage(strconv.FormatInt(date.UnixMilli(), 10))
		}
	}
	switch output := result.Output.(type) {
	case *api.StartExecutionOutput:
		setDate("StartDate", output.StartDate)
		if err := stepFunctionsAddMetadata(document, result); err != nil {
			return nil, err
		}
	case *api.DescribeExecutionOutput:
		setDate("StartDate", output.StartDate)
		setDate("StopDate", output.StopDate)
		setDate("RedriveDate", output.RedriveDate)
		if objects {
			for _, field := range []string{"Input", "Output"} {
				if raw, present := document[field]; present {
					var text string
					if err := json.Unmarshal(raw, &text); err != nil {
						return nil, err
					}
					if !json.Valid([]byte(text)) {
						return nil, fmt.Errorf("nested execution %s is not valid JSON", field)
					}
					document[field] = json.RawMessage(text)
				}
			}
		}
	default:
		return nil, fmt.Errorf("unsupported nested execution output %T", result.Output)
	}
	return json.Marshal(document)
}
