package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"stackd/internal/awsapi"
	eventsapi "stackd/internal/awsapi/eventbridge"
	lambdaapi "stackd/internal/awsapi/lambda"
	"stackd/internal/services/stepfunctions"
)

func (t *StepFunctionsTasks) runOptimizedTask(ctx context.Context, task stepfunctions.TaskRecord, revision stepfunctions.RevisionRecord, service, operation string) (stepfunctions.TaskOutcome, error) {
	allowed := (service == "sqs" && operation == "sendMessage") || (service == "sns" && operation == "publish") ||
		(service == "events" && operation == "putEvents") ||
		(service == "dynamodb" && (operation == "getItem" || operation == "putItem" || operation == "updateItem" || operation == "deleteItem"))
	if !allowed || task.Kind == "sync" || (task.Kind == "callback" && service != "sqs" && service != "sns") {
		// TODO: Comeback connect remaining optimized task resources and completion patterns to their real service owners.
		return stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: "Unsupported optimized task resource: " + task.Resource}, nil
	}
	parameters, err := stepFunctionsJSONObject(task.Parameters)
	if err != nil {
		return stepfunctions.TaskOutcome{Error: "States.Runtime", Cause: err.Error()}, nil
	}
	if service == "sqs" {
		stepFunctionsStringifyMember(parameters, "MessageBody")
	}
	if service == "sns" {
		stepFunctionsStringifyMember(parameters, "Message")
	}
	if service == "events" {
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(parameters["Entries"], &entries); err != nil {
			return stepfunctions.TaskOutcome{Error: "States.Runtime", Cause: err.Error()}, nil
		}
		for _, entry := range entries {
			if entry == nil {
				return stepfunctions.TaskOutcome{Error: "States.Runtime", Cause: "EventBridge Entries must contain objects."}, nil
			}
			stepFunctionsStringifyMember(entry, "Detail")
			var resources []string
			if raw, present := entry["Resources"]; present {
				if err := json.Unmarshal(raw, &resources); err != nil {
					return stepfunctions.TaskOutcome{Error: "States.Runtime", Cause: err.Error()}, nil
				}
			}
			resources = append(resources, task.Frame.Execution.ARN, revision.Machine.ARN())
			entry["Resources"], err = json.Marshal(resources)
			if err != nil {
				return stepfunctions.TaskOutcome{}, err
			}
		}
		parameters["Entries"], err = json.Marshal(entries)
		if err != nil {
			return stepfunctions.TaskOutcome{}, err
		}
	}
	input, err := json.Marshal(parameters)
	if err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	result, wire := t.Commands.CallResponse(ctx, service, operation, input)
	if wire != nil {
		return stepFunctionsCommandFailure(result, wire, true), nil
	}
	output, err := awsapi.EncodeDocument(result.Service, result.Operation.Output, result.Output, nil)
	if err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	if put, ok := result.Output.(*eventsapi.PutEventsResponse); ok && put != nil && put.FailedEntryCount != nil && *put.FailedEntryCount > 0 {
		return stepfunctions.TaskOutcome{Error: "EventBridge.FailedEntry", Cause: string(output)}, nil
	}
	output, err = stepFunctionsOptimizedOutput(result, output)
	if err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	return stepfunctions.TaskOutcome{Output: string(output)}, nil
}

func stepFunctionsStringifyMember(object map[string]json.RawMessage, name string) {
	if value, present := object[name]; present && (len(value) == 0 || value[0] != '"') {
		object[name] = stepFunctionsJSONString(value)
	}
}

func (t *StepFunctionsTasks) runLambdaTask(ctx context.Context, task stepfunctions.TaskRecord, direct bool) (stepfunctions.TaskOutcome, error) {
	if task.Kind == "sync" {
		return stepfunctions.TaskOutcome{Error: "States.TaskFailed", Cause: "Lambda does not support the Run a Job pattern."}, nil
	}
	var parameters map[string]json.RawMessage
	if direct {
		name, err := json.Marshal(task.Resource)
		if err != nil {
			return stepfunctions.TaskOutcome{}, err
		}
		// A direct ARN consumes the whole state input, not an Invoke envelope.
		parameters = map[string]json.RawMessage{"FunctionName": name, "Payload": stepFunctionsJSONString(json.RawMessage(task.Parameters))}
	} else {
		var err error
		parameters, err = stepFunctionsJSONObject(task.Parameters)
		if err != nil {
			return stepfunctions.TaskOutcome{Error: "States.Runtime", Cause: err.Error()}, nil
		}
	}
	input, err := json.Marshal(parameters)
	if err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	call := t.Commands.CallResponse
	if direct {
		call = t.Commands.Call
	}
	result, wire := call(ctx, "lambda", "Invoke", input)
	if wire != nil {
		return stepFunctionsCommandFailure(result, wire, true), nil
	}
	response, ok := result.Output.(*lambdaapi.InvocationResponse)
	if !ok || response == nil {
		return stepfunctions.TaskOutcome{}, fmt.Errorf("lambda Invoke returned %T instead of InvocationResponse", result.Output)
	}
	if response.FunctionError != nil && *response.FunctionError != "" {
		var failure struct {
			ErrorType string `json:"errorType"`
		}
		_ = json.Unmarshal(response.Payload, &failure)
		if failure.ErrorType == "" {
			failure.ErrorType = "Lambda.Unknown"
		}
		cause := string(response.Payload)
		if !direct {
			var compact bytes.Buffer
			if json.Compact(&compact, response.Payload) == nil {
				cause = compact.String()
			}
		}
		return stepfunctions.TaskOutcome{Error: failure.ErrorType, Cause: cause}, nil
	}
	if direct {
		if len(response.Payload) == 0 {
			return stepfunctions.TaskOutcome{Output: "null"}, nil
		}
		if !json.Valid(response.Payload) {
			return stepfunctions.TaskOutcome{Error: "States.Runtime", Cause: "Lambda returned a payload that is not valid JSON."}, nil
		}
		return stepfunctions.TaskOutcome{Output: string(response.Payload)}, nil
	}
	output, err := awsapi.EncodeDocument(result.Service, result.Operation.Output, response, nil)
	if err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(output, &document); err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	if document == nil {
		return stepfunctions.TaskOutcome{}, errors.New("lambda Invoke returned no response document")
	}
	document["Payload"] = json.RawMessage("null")
	if len(response.Payload) != 0 {
		if !json.Valid(response.Payload) {
			return stepfunctions.TaskOutcome{Error: "States.Runtime", Cause: "Lambda returned a payload that is not valid JSON."}, nil
		}
		document["Payload"] = json.RawMessage(response.Payload)
	}
	if err := stepFunctionsAddMetadata(document, result); err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	output, err = json.Marshal(document)
	if err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	return stepfunctions.TaskOutcome{Output: string(output)}, nil
}
