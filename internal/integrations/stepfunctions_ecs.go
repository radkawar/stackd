package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awscatalog"
	"stackd/internal/services/stepfunctions"
)

func (t *StepFunctionsTasks) runECSTask(ctx context.Context, task stepfunctions.TaskRecord, revision stepfunctions.RevisionRecord, submit func(stepfunctions.TaskOutcome) error) (stepfunctions.TaskOutcome, error) {
	synchronous := task.Kind == "sync"
	if (synchronous || task.Kind == "callback") && submit == nil {
		return stepfunctions.TaskOutcome{}, errors.New("ECS task has no submission sink")
	}
	var completion *stepFunctionsECSCompletion
	if synchronous {
		var unsubscribe func()
		completion, unsubscribe = t.subscribeECS(ctx)
		defer unsubscribe()
	}
	accepted := task.Output
	if accepted == "" {
		parameters, err := stepFunctionsJSONObject(task.Parameters)
		if err != nil {
			return stepfunctions.TaskOutcome{Error: "States.Runtime", Cause: err.Error()}, nil
		}
		if synchronous {
			for _, name := range []string{"Count", "StartedBy"} {
				if _, present := parameters[name]; present {
					return stepfunctions.TaskOutcome{Error: "States.Runtime", Cause: "The field '" + name + "' is not supported by Step Functions"}, nil
				}
			}
			parameters["StartedBy"] = json.RawMessage(`"AWS Step Functions"`)
		}
		if _, provided := parameters["ClientToken"]; !provided {
			// The ECS owner already retains idempotent RunTask requests. Use
			// the committed attempt identity across the accept-to-submit gap,
			// without introducing a second job ledger or changing explicit tokens.
			parameters["ClientToken"], _ = json.Marshal(task.Key.ID)
		}
		input, err := json.Marshal(parameters)
		if err != nil {
			return stepfunctions.TaskOutcome{}, err
		}
		result, wire := t.Commands.CallResponse(ctx, "ecs", "RunTask", input)
		if wire != nil {
			return stepFunctionsCommandFailure(result, wire, true), nil
		}
		response, ok := result.Output.(*api.RunTaskOutput)
		if !ok || response == nil {
			return stepfunctions.TaskOutcome{}, fmt.Errorf("RunTask returned %T", result.Output)
		}
		output, err := stepFunctionsECSOutput(result)
		if err != nil {
			return stepfunctions.TaskOutcome{}, err
		}
		if len(response.Failures) != 0 && (synchronous || task.Kind == "callback") {
			return stepfunctions.TaskOutcome{Error: "AmazonECS.Unknown", Cause: string(output)}, nil
		}
		outcome := stepfunctions.TaskOutcome{Output: string(output), Submitted: synchronous || task.Kind == "callback"}
		if outcome.Submitted {
			if err := submit(outcome); err != nil {
				if synchronous && !errors.Is(context.Cause(ctx), stepfunctions.ErrTaskInterrupted) {
					for _, acceptedTask := range response.Tasks {
						if acceptedTask.TaskArn != nil && acceptedTask.ClusterArn != nil {
							t.stopECSTask(ctx, task, revision, string(*acceptedTask.ClusterArn), string(*acceptedTask.TaskArn))
						}
					}
				}
				return stepfunctions.TaskOutcome{}, err
			}
		}
		if !synchronous {
			return outcome, nil
		}
		accepted = outcome.Output
	}
	if !synchronous {
		return stepfunctions.TaskOutcome{}, errors.New("only synchronous ECS tasks can resume an accepted job")
	}
	var response struct {
		Tasks []struct{ TaskArn, ClusterArn string }
	}
	if err := json.Unmarshal([]byte(accepted), &response); err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	if len(response.Tasks) != 1 || response.Tasks[0].TaskArn == "" || response.Tasks[0].ClusterArn == "" {
		return stepfunctions.TaskOutcome{}, errors.New("synchronous RunTask returned no unique task identity")
	}
	arn, cluster := response.Tasks[0].TaskArn, response.Tasks[0].ClusterArn
	t.selectECSTask(completion, arn)
	defer func() {
		if ctx.Err() != nil && !errors.Is(context.Cause(ctx), stepfunctions.ErrTaskInterrupted) {
			t.stopECSTask(ctx, task, revision, cluster, arn)
		}
	}()
	stopped, failure, err := t.waitECSTask(ctx, task, revision, cluster, arn, completion)
	if err != nil || failure.Error != "" {
		return failure, err
	}
	return stepFunctionsECSCompletionOutput(stopped)
}

func (t *StepFunctionsTasks) waitECSTask(ctx context.Context, task stepfunctions.TaskRecord, revision stepfunctions.RevisionRecord, cluster, arn string, completion *stepFunctionsECSCompletion) (*api.Task, stepfunctions.TaskOutcome, error) {
	parameters, err := json.Marshal(map[string]any{"Cluster": cluster, "Tasks": []string{arn}})
	if err != nil {
		return nil, stepfunctions.TaskOutcome{}, err
	}
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	scoped, renewAt := ctx, time.Now().Add(30*time.Minute)
	reconcile := task.Output != ""
	for {
		if !reconcile {
			select {
			case <-ctx.Done():
				return nil, stepfunctions.TaskOutcome{}, ctx.Err()
			case <-completion.wake:
			case <-poll.C:
			}
		}
		reconcile = false
		if t.ecsTaskDelivered(completion) {
			if t.ECS == nil {
				return nil, stepfunctions.TaskOutcome{}, errors.New("ECS completion observer is not configured")
			}
			stopped, err := t.ECS.ObserveTaskCompletion(ctx, arn)
			return stopped, stepfunctions.TaskOutcome{}, err
		}
		if !time.Now().Before(renewAt) {
			// A managed delivery remains usable even if role renewal or polling
			// is denied after admission. Public polls still enforce current IAM.
			renewed, failure, err := t.taskContext(ctx, task, revision)
			if err == nil && failure.Error == "" {
				scoped = renewed
			}
			renewAt = time.Now().Add(30 * time.Minute)
		}
		result, wire := t.Commands.Call(scoped, "ecs", "DescribeTasks", parameters)
		if wire != nil {
			if wire.Code == "AccessDenied" || wire.Code == "AccessDeniedException" {
				continue
			}
			return nil, stepFunctionsCommandFailure(result, wire, true), nil
		}
		response, ok := result.Output.(*api.DescribeTasksOutput)
		if !ok || response == nil {
			return nil, stepfunctions.TaskOutcome{}, fmt.Errorf("DescribeTasks returned %T", result.Output)
		}
		if len(response.Failures) != 0 {
			output, err := stepFunctionsECSOutput(result)
			return nil, stepfunctions.TaskOutcome{Error: "AmazonECS.Unknown", Cause: string(output)}, err
		}
		for _, observed := range response.Tasks {
			if observed.TaskArn != nil && string(*observed.TaskArn) == arn && observed.LastStatus != nil && *observed.LastStatus == "STOPPED" {
				if t.ECS == nil {
					return nil, stepfunctions.TaskOutcome{}, errors.New("ECS completion observer is not configured")
				}
				stopped, err := t.ECS.ObserveTaskCompletion(ctx, arn)
				return stopped, stepfunctions.TaskOutcome{}, err
			}
		}
	}
}

func (t *StepFunctionsTasks) stopECSTask(ctx context.Context, task stepfunctions.TaskRecord, revision stepfunctions.RevisionRecord, cluster, arn string) {
	completion, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	scoped, failure, err := t.taskContext(completion, task, revision)
	if err != nil || failure.Error != "" {
		return
	}
	parameters, err := json.Marshal(map[string]string{"Cluster": cluster, "Task": arn, "Reason": "The Step Functions task was cancelled."})
	if err != nil {
		return
	}
	_, _ = t.Commands.Call(scoped, "ecs", "StopTask", parameters)
}

func stepFunctionsECSOutput(result StepFunctionsCommandResult) ([]byte, error) {
	encoded, err := awsapi.EncodeOptimizedSDKDocument(result.Service, result.Operation.Output, result.Output)
	if err != nil || result.Response.StatusCode == 0 {
		return encoded, err
	}
	return stepFunctionsOptimizedOutput(result, encoded)
}

func stepFunctionsECSCompletionOutput(task *api.Task) (stepfunctions.TaskOutcome, error) {
	if task == nil {
		return stepfunctions.TaskOutcome{}, errors.New("ECS completion returned no task")
	}
	service, ok := awscatalog.LookupService("ecs")
	if !ok {
		return stepfunctions.TaskOutcome{}, errors.New("ECS model is unavailable")
	}
	encoded, err := awsapi.EncodeOptimizedSDKDocument(service, "com.amazonaws.ecs#Task", task)
	if err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	output := string(encoded)
	if task.StopCode != nil && *task.StopCode == "TaskFailedToStart" {
		return stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: output}, nil
	}
	for _, container := range task.Containers {
		if container.ExitCode != nil && *container.ExitCode != 0 {
			return stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: output}, nil
		}
	}
	return stepfunctions.TaskOutcome{Output: output}, nil
}
