package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type stepFunctionsCommandProvider struct {
	model    awscatalog.Service
	executor awscommands.CommandExecutor
}

// StepFunctionsCommands invokes the same typed authorization and transaction
// boundary as the frontend. Its provider set is fixed during instance assembly.
type StepFunctionsCommands struct {
	providers map[string]stepFunctionsCommandProvider
}

// NewStepFunctionsCommands derives SDK names from the generated model inputs;
// there is no second hand-maintained operation registry.
func NewStepFunctionsCommands(executors map[string]awscommands.CommandExecutor) StepFunctionsCommands {
	commands := StepFunctionsCommands{providers: make(map[string]stepFunctionsCommandProvider, len(executors)*3)}
	for name, executor := range executors {
		model, ok := awscatalog.LookupService(name)
		if !ok {
			continue
		}
		provider := stepFunctionsCommandProvider{model: model, executor: executor}
		commands.providers[name] = provider
		commands.providers[strings.ToLower(strings.ReplaceAll(model.SDKID, " ", ""))] = provider
		commands.providers[strings.TrimSuffix(path.Base(model.Source.Path), ".json")] = provider
	}
	return commands
}

// StepFunctionsCommandResult keeps a typed output attached to its authoritative
// model; optimized and SDK integrations choose their own native projection.
type StepFunctionsCommandResult struct {
	Service   awscatalog.Service
	Operation awscatalog.Operation
	Output    any
	// Response is populated only when a caller consumes response metadata.
	Response  awsapi.HTTPResponse
	RequestID string
}

func (c StepFunctionsCommands) resolve(service, operation string) (stepFunctionsCommandProvider, StepFunctionsCommandResult, *awswire.Error) {
	provider, ok := c.providers[service]
	if !ok {
		return provider, StepFunctionsCommandResult{}, &awswire.Error{Code: "NotImplemented", Message: "AWS SDK service is not implemented: " + service, StatusCode: 501}
	}
	result := StepFunctionsCommandResult{Service: provider.model}
	if operation != "" {
		operation = strings.ToUpper(operation[:1]) + operation[1:]
	}
	op, ok := provider.model.Operation(operation)
	if !ok {
		return provider, result, &awswire.Error{Code: "UnknownOperationException", Message: "Unknown operation: " + operation, StatusCode: 400}
	}
	result.Operation = op
	if sdkEventStream(provider.model, op.Input) || sdkEventStream(provider.model, op.Output) {
		return provider, result, &awswire.Error{Code: "UnsupportedOperation", Message: "Step Functions does not support event-stream SDK operations.", StatusCode: 400}
	}
	return provider, result, nil
}

func sdkEventStream(service awscatalog.Service, id awscatalog.ShapeID) bool {
	shape, _ := service.Shape(id)
	if shape.Streaming && shape.Kind == "union" {
		return true
	}
	for _, member := range shape.Members {
		child, _ := service.Shape(member.Target)
		if child.Streaming && child.Kind == "union" {
			return true
		}
	}
	return false
}

func (c StepFunctionsCommands) Call(ctx context.Context, service, operation string, parameters json.RawMessage) (StepFunctionsCommandResult, *awswire.Error) {
	return c.call(ctx, service, operation, parameters, awsapi.DecodeSDKInput, false)
}

// CallResponse additionally retains the service-owned response for optimized
// integrations. Ordinary SDK tasks do not need a second wire serialization.
func (c StepFunctionsCommands) CallResponse(ctx context.Context, service, operation string, parameters json.RawMessage) (StepFunctionsCommandResult, *awswire.Error) {
	return c.call(ctx, service, operation, parameters, awsapi.DecodeSDKInput, true)
}

// callCloudFormation keeps resource scalar normalization separate from the
// Step Functions SDK input contract, while retaining the same service owner.
func (c StepFunctionsCommands) callCloudFormation(ctx context.Context, service, operation string, parameters json.RawMessage) (StepFunctionsCommandResult, *awswire.Error) {
	return c.call(ctx, service, operation, parameters, awsapi.DecodeCloudFormationInput, false)
}

func (c StepFunctionsCommands) call(ctx context.Context, service, operation string, parameters json.RawMessage, decodeInput func(awscatalog.Service, awscatalog.Operation, []byte, any) error, response bool) (StepFunctionsCommandResult, *awswire.Error) {
	provider, result, wireErr := c.resolve(service, operation)
	if wireErr != nil {
		return result, wireErr
	}
	input, err := awscommands.NewInput(result.Service.Name, string(result.Operation.Name))
	if err != nil {
		return result, &awswire.Error{Code: "NotImplemented", Message: err.Error(), StatusCode: 501}
	}
	if err := decodeInput(result.Service, result.Operation, parameters, input); err != nil {
		return result, &awswire.Error{Code: "ValidationException", Message: err.Error(), StatusCode: 400}
	}
	return c.execute(ctx, provider, result, input, parameters, response)
}

// CallTyped preserves real binary payloads for service-owned operations such as
// a Map ResultWriter. Callers construct generated DTOs; destination services
// retain their normal semantic validation, authorization and audit ownership.
func (c StepFunctionsCommands) CallTyped(ctx context.Context, service, operation string, input any) (StepFunctionsCommandResult, *awswire.Error) {
	provider, result, wireErr := c.resolve(service, operation)
	if wireErr != nil {
		return result, wireErr
	}
	if input == nil {
		return result, &awswire.Error{Code: "ValidationException", Message: fmt.Sprintf("Missing input for %s", operation), StatusCode: 400}
	}
	return c.execute(ctx, provider, result, input, nil, false)
}

func (c StepFunctionsCommands) execute(ctx context.Context, provider stepFunctionsCommandProvider, result StepFunctionsCommandResult, input any, body []byte, response bool) (StepFunctionsCommandResult, *awswire.Error) {
	if err := awsapi.PrepareSDKChecksums(result.Service, result.Operation, input); err != nil {
		return result, &awswire.Error{Code: "ValidationException", Message: err.Error(), StatusCode: 400}
	}
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID = uuid.NewString()
	result.RequestID = metadata.RequestID
	ctx = awsctx.WithMetadata(ctx, metadata)
	observer, _ := ctx.Value(stepFunctionsTraceObserverKey{}).(*stepFunctionsTraceObserver)
	var span string
	var started time.Time
	if observer != nil {
		ctx, span, started = observer.begin(ctx)
	}
	decoded := awsapi.DecodedRequest{Operation: result.Operation, Protocol: result.Service.Protocol, Input: input, Body: body}
	var rejected *awswire.Error
	if encoder, ok := provider.executor.(stepFunctionsResponseExecutor); response && ok {
		result.Output, result.Response, rejected = encoder.ExecuteCommandResponse(ctx, decoded)
	} else {
		result.Output, rejected = provider.executor.ExecuteCommand(ctx, decoded)
		if rejected == nil && response {
			var err error
			result.Response, err = stepFunctionsCommandResponse(result)
			if err != nil {
				rejected = &awswire.Error{Code: "InternalFailure", Message: "Unable to encode command response.", StatusCode: 500, Cause: err}
			}
		}
	}
	if observer != nil {
		observer.finish(ctx, span, started, result, input, rejected)
	}
	return result, rejected
}
