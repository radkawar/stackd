package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	ecsapi "stackd/internal/awsapi/ecs"
	stepfunctionsapi "stackd/internal/awsapi/stepfunctions"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/stepfunctions"
)

// StepFunctionsExecutions owns retained execution observation and Map child
// authorization; the adapter supplies an actual assumed execution-role context.
type StepFunctionsExecutions interface {
	WaitExecution(context.Context, string) (*stepfunctionsapi.DescribeExecutionOutput, error)
	AuthorizeMapExecutions(context.Context, string) *awswire.Error
}

type StepFunctionsSyncRules interface {
	ConfigureStepFunctionsSync(context.Context) *awswire.Error
	ConfigureStepFunctionsECSSync(context.Context) *awswire.Error
}

// StepFunctionsECSTasks projects retained completion after either a matching
// managed EventBridge delivery or an authorized terminal DescribeTasks result.
type StepFunctionsECSTasks interface {
	ObserveTaskCompletion(context.Context, string) (*ecsapi.Task, error)
}

// StepFunctionsTasks is an effect adapter, not an execution interpreter. The
// source engine commits task attempts before calling Run and owns their clocks.
type StepFunctionsTasks struct {
	Roles       ServiceRoles
	Commands    StepFunctionsCommands
	Executions  StepFunctionsExecutions
	SyncRules   StepFunctionsSyncRules
	ECS         StepFunctionsECSTasks
	Tracing     *StepFunctionsTracing
	Connections StepFunctionsConnections
	HTTPClient  *http.Client

	completionsMu  sync.Mutex
	completions    map[string]map[chan struct{}]struct{}
	ecsCompletions map[string]map[*stepFunctionsECSCompletion]struct{}
}

// ConfigureTaskDependencies runs after the control owner validates the actual
// definition and releases its resource transaction.
func (t *StepFunctionsTasks) ConfigureTaskDependencies(ctx context.Context, revision stepfunctions.RevisionRecord) error {
	if t.SyncRules == nil {
		return errors.New("step functions managed-rule dependency is not configured")
	}
	origin := awsctx.FromContext(ctx)
	parent := apievents.EventID(ctx)
	if parent == "" {
		parent = origin.ParentEventID
	}
	key := revision.Machine
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ParentEventID: parent})
	credential, wire := t.Roles.assume(ctx,
		awsctx.ServicePrincipal{Name: "states.amazonaws.com", SourceARN: key.ARN(), Type: "AWSService"},
		revision.RoleARN, identity.RoleSessionSpec{SessionName: "StepFunctions_Events"}, "")
	if wire == nil {
		var role context.Context
		role, wire = serviceRoleRequestContext(ctx, credential, key.Region, "states.amazonaws.com")
		if wire == nil && revision.NeedsNestedSync {
			wire = t.SyncRules.ConfigureStepFunctionsSync(role)
		}
		if wire == nil && revision.NeedsECSSync {
			wire = t.SyncRules.ConfigureStepFunctionsECSSync(role)
		}
	}
	if wire == nil {
		return nil
	}
	if wire.StatusCode >= 500 {
		return wire
	}
	return &awswire.Error{Code: "AccessDeniedException", Message: "'" + revision.RoleARN + "' is not authorized to create managed-rule.", StatusCode: 400, Cause: wire}
}

func (t *StepFunctionsTasks) Run(ctx context.Context, task stepfunctions.TaskRecord, revision stepfunctions.RevisionRecord, submit func(stepfunctions.TaskOutcome) error) (stepfunctions.TaskOutcome, error) {
	if err := ctx.Err(); err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	if task.Kind == "activity" {
		return stepfunctions.TaskOutcome{}, errors.New("activities must be dispatched by GetActivityTask")
	}
	ctx, failure, err := t.taskContext(ctx, task, revision)
	if err != nil || failure.Error != "" {
		return failure, err
	}
	if t.Tracing != nil {
		ctx = t.Tracing.taskContext(ctx, task, revision)
	}
	if task.Kind == "MAP_EXECUTIONS" || task.Kind == "MAP_REDRIVE" {
		if denied := t.Executions.AuthorizeMapExecutions(ctx, task.Resource); denied != nil {
			if denied.StatusCode >= 500 {
				return stepfunctions.TaskOutcome{}, denied
			}
			return stepfunctions.TaskOutcome{Error: "States.Runtime", Cause: denied.Message}, nil
		}
		return stepfunctions.TaskOutcome{Output: "{}"}, nil
	}
	if task.Kind == "MAP_READER" || task.Kind == "MAP_WRITER" {
		return t.runMapTask(ctx, task, revision)
	}
	parts := strings.SplitN(task.Resource, ":", 6)
	if len(parts) != 6 {
		return stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: "Invalid task resource: " + task.Resource}, nil
	}
	if parts[2] == "lambda" {
		return t.runLambdaTask(ctx, task, true)
	}
	if parts[2] != "states" {
		return stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: "Unsupported task resource: " + task.Resource}, nil
	}
	resource := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(parts[5], ".waitForTaskToken"), ".sync:2"), ".sync")
	var outcome stepfunctions.TaskOutcome
	if sdk, ok := strings.CutPrefix(resource, "aws-sdk:"); ok {
		service, operation, valid := strings.Cut(sdk, ":")
		if !valid || service == "" || operation == "" {
			return stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: "Invalid AWS SDK task resource: " + task.Resource}, nil
		}
		if task.Kind == "sync" {
			return stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: "AWS SDK integrations do not support the Run a Job pattern."}, nil
		}
		result, wire := t.Commands.Call(ctx, service, operation, json.RawMessage(task.Parameters))
		if wire != nil {
			return stepFunctionsCommandFailure(result, wire, false), nil
		}
		output, encodeErr := awsapi.EncodeSDKOutput(result.Service, result.Operation, result.Output)
		if encodeErr != nil {
			return stepfunctions.TaskOutcome{}, encodeErr
		}
		outcome.Output = string(output)
	} else {
		service, operation, valid := strings.Cut(resource, ":")
		if !valid {
			return stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: "Invalid optimized task resource: " + task.Resource}, nil
		}
		switch {
		case service == "states" && operation == "startExecution":
			return t.runNestedTask(ctx, task, revision, submit)
		case service == "ecs" && operation == "runTask":
			return t.runECSTask(ctx, task, revision, submit)
		case service == "lambda" && operation == "invoke":
			outcome, err = t.runLambdaTask(ctx, task, false)
		case service == "http" && operation == "invoke":
			outcome, err = t.runHTTPTask(ctx, task, revision)
		default:
			outcome, err = t.runOptimizedTask(ctx, task, revision, service, operation)
		}
	}
	if err != nil || outcome.Error != "" {
		return outcome, err
	}
	if task.Kind == "callback" {
		outcome.Submitted = true
		if submit == nil {
			return stepfunctions.TaskOutcome{}, errors.New("callback task has no submission sink")
		}
		if err := submit(outcome); err != nil {
			return stepfunctions.TaskOutcome{}, err
		}
	}
	return outcome, nil
}

func (t *StepFunctionsTasks) taskContext(ctx context.Context, task stepfunctions.TaskRecord, revision stepfunctions.RevisionRecord) (context.Context, stepfunctions.TaskOutcome, error) {
	observer, _ := ctx.Value(stepFunctionsTraceObserverKey{}).(*stepFunctionsTraceObserver)
	if observer != nil {
		ctx = context.WithValue(ctx, stepFunctionsTraceObserverKey{}, (*stepFunctionsTraceObserver)(nil))
	}
	original := awsctx.FromContext(ctx)
	original.AccountID, original.Region, original.Partition = task.Key.Scope.AccountID, task.Key.Scope.Region, task.Key.Scope.Partition
	ctx = awsctx.WithMetadata(ctx, original)
	source := awsctx.ServicePrincipal{Name: "states.amazonaws.com", SourceARN: revision.Machine.ARN(), Type: "AWSService"}
	// The source ARN remains the machine, not the mutable destination or caller.
	// In particular Credentials does not let states assume the override directly.
	credential, wire := t.Roles.assume(ctx, source, revision.RoleARN, identity.RoleSessionSpec{SessionName: "stepfunctions-" + task.Key.ID}, "")
	if wire != nil {
		if wire.StatusCode >= 500 {
			return nil, stepfunctions.TaskOutcome{}, wire
		}
		return nil, stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: "The principal states.amazonaws.com is not authorized to assume the provided role. (role: " + revision.RoleARN + ")"}, nil
	}
	scoped, wire := serviceRoleRequestContext(ctx, credential, original.Region, source.Name)
	if wire != nil {
		return nil, stepfunctions.TaskOutcome{}, wire
	}
	metadata := awsctx.FromContext(scoped)
	metadata.TraceHeader = original.TraceHeader
	scoped = awsctx.WithMetadata(scoped, metadata)
	if task.RoleARN != "" && task.RoleARN != revision.RoleARN {
		parameters, err := json.Marshal(map[string]string{"RoleArn": task.RoleARN, "RoleSessionName": "stepfunctions-" + task.Key.ID, "ExternalId": revision.Machine.ARN()})
		if err != nil {
			return nil, stepfunctions.TaskOutcome{}, err
		}
		result, wire := t.Commands.Call(scoped, "sts", "AssumeRole", parameters)
		if wire != nil {
			return nil, stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: wire.Message}, nil
		}
		assumed, ok := result.Output.(*stsapi.AssumeRoleOutput)
		if !ok || assumed == nil || assumed.Credentials == nil || assumed.Credentials.AccessKeyId == nil {
			return nil, stepfunctions.TaskOutcome{}, errors.New("STS AssumeRole returned no credentials")
		}
		credential, err := t.Roles.Credentials.Resolve(scoped, string(*assumed.Credentials.AccessKeyId))
		if err != nil {
			return nil, stepfunctions.TaskOutcome{}, err
		}
		scoped, wire = serviceRoleRequestContext(scoped, credential, original.Region, source.Name)
		if wire != nil {
			return nil, stepfunctions.TaskOutcome{}, wire
		}
		metadata = awsctx.FromContext(scoped)
		metadata.TraceHeader = original.TraceHeader
		scoped = awsctx.WithMetadata(scoped, metadata)
	}
	if observer != nil {
		scoped = context.WithValue(scoped, stepFunctionsTraceObserverKey{}, observer)
	}
	return scoped, stepfunctions.TaskOutcome{}, nil
}

func stepFunctionsCommandFailure(result StepFunctionsCommandResult, wire *awswire.Error, optimized bool) stepfunctions.TaskOutcome {
	prefix := stepFunctionsErrorPrefix(result.Service, optimized)
	if prefix == "" {
		return stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: wire.Message}
	}
	name := stepFunctionsErrorPrefix(result.Service, false) + "Exception"
	if optimized && result.Service.Name == "ecs" {
		name = wire.Code
		if !strings.HasSuffix(name, "Exception") {
			name += "Exception"
		}
	}
	if shape, ok := result.Service.ErrorShape(wire.Code); ok {
		_, name, _ = strings.Cut(string(shape.ID), "#")
		if !strings.HasSuffix(name, "Exception") {
			name += "Exception"
		}
	}
	cause := wire.Message
	if optimized && result.Service.Name == "ecs" && result.RequestID != "" {
		cause = fmt.Sprintf("%s (Service: AmazonECS; Status Code: %d; Error Code: %s; Request ID: %s; Proxy: null)", cause, wire.StatusCode, wire.Code, result.RequestID)
	}
	return stepfunctions.TaskOutcome{Error: prefix + "." + name, Cause: cause}
}

func stepFunctionsErrorPrefix(service awscatalog.Service, optimized bool) string {
	if optimized {
		switch service.Name {
		case "dynamodb":
			return "DynamoDB"
		case "sqs":
			return "SQS"
		case "sns":
			return "SNS"
		case "eventbridge":
			return "EventBridge"
		case "ecs":
			return "ECS"
		case "stepfunctions":
			return "StepFunctions"
		}
	}
	switch service.Name {
	case "sqs":
		return "Sqs"
	case "sns":
		return "Sns"
	case "sts":
		return "Sts"
	case "iam":
		return "Iam"
	case "kms":
		return "Kms"
	case "ecs":
		return "Ecs"
	case "ec2":
		return "Ec2"
	case "xray":
		return "XRay"
	case "dynamodb":
		return "DynamoDb"
	case "dynamodbstreams":
		return "DynamoDbStreams"
	case "stepfunctions":
		return "Sfn"
	case "logs":
		return "CloudWatchLogs"
	}
	return strings.ReplaceAll(service.SDKID, " ", "")
}

func stepFunctionsJSONObject(parameters string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(parameters), &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, fmt.Errorf("task parameters must be a JSON object")
	}
	return object, nil
}

func stepFunctionsJSONString(value json.RawMessage) json.RawMessage {
	encoded, _ := json.Marshal(string(value))
	return encoded
}
