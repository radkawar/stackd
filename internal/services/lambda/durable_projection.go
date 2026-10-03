package lambda

import (
	"time"

	api "stackd/internal/awsapi/lambda"
)

func durableOptional[T ~string](value string) *T {
	if value == "" {
		return nil
	}
	return new(T(value))
}

func durableTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return new(value)
}

func durablePayload(value *string) *api.OperationPayload {
	if value == nil {
		return nil
	}
	return new(api.OperationPayload(*value))
}

func durableOperation(op DurableOperationRecord) api.Operation {
	out := api.Operation{Id: new(api.OperationId(op.ID)), Type: new(api.OperationType(op.Type)), Status: new(api.OperationStatus(op.Status)), Name: durableOptional[api.OperationName](op.Name), ParentId: durableOptional[api.OperationId](op.ParentID), SubType: durableOptional[api.OperationSubType](op.SubType), StartTimestamp: new(op.StartedAt), EndTimestamp: durableTime(op.EndedAt)}
	switch op.Type {
	case "EXECUTION":
		out.ExecutionDetails = &api.ExecutionDetails{}
		if op.Payload != nil {
			out.ExecutionDetails.InputPayload = new(api.InputPayload(*op.Payload))
		}
	case "STEP":
		out.StepDetails = &api.StepDetails{Attempt: new(api.AttemptCount(op.Attempt)), Result: durablePayload(op.Payload), Error: cloneDurableError(op.Error), NextAttemptTimestamp: durableTime(op.DueAt)}
	case "CONTEXT":
		out.ContextDetails = &api.ContextDetails{Result: durablePayload(op.Payload), Error: cloneDurableError(op.Error), ReplayChildren: new(api.ReplayChildren(op.ReplayChildren))}
	case "WAIT":
		out.WaitDetails = &api.WaitDetails{ScheduledEndTimestamp: durableTime(op.DueAt)}
	case "CALLBACK":
		out.CallbackDetails = &api.CallbackDetails{CallbackId: new(api.CallbackId(op.CallbackID)), Result: durablePayload(op.Payload), Error: cloneDurableError(op.Error)}
	case "CHAINED_INVOKE":
		out.ChainedInvokeDetails = &api.ChainedInvokeDetails{Result: durablePayload(op.Payload), Error: cloneDurableError(op.Error)}
	}
	return out
}

func durableOperations(operations []DurableOperationRecord) api.Operations {
	out := make(api.Operations, 0, len(operations))
	hidden := make(map[string]bool)
	for _, op := range operations {
		if hidden[op.ParentID] {
			hidden[op.ID] = true
			continue
		}
		out = append(out, durableOperation(op))
		if op.Type == "CONTEXT" && durableTerminal(op.Status) && !op.ReplayChildren {
			hidden[op.ID] = true
		}
	}
	return out
}

func durableHistoryEvent(event DurableEventRecord, execution DurableExecutionRecord, data bool) api.Event {
	op := event.Operation
	out := api.Event{EventId: new(api.EventId(event.ID)), EventTimestamp: new(event.At), EventType: new(api.EventType(event.Type)), Id: new(api.OperationId(op.ID)), Name: durableOptional[api.OperationName](op.Name), ParentId: durableOptional[api.OperationId](op.ParentID), SubType: durableOptional[api.OperationSubType](op.SubType)}
	result := &api.EventResult{Truncated: new(api.Truncated(!data))}
	err := &api.EventError{Truncated: new(api.Truncated(!data))}
	input := &api.EventInput{Truncated: new(api.Truncated(!data))}
	if data {
		result.Payload, err.Payload = durablePayload(op.Payload), cloneDurableError(op.Error)
		if op.Payload != nil {
			input.Payload = new(api.InputPayload(*op.Payload))
		}
	}
	retry := &api.RetryDetails{CurrentAttempt: new(api.AttemptCount(op.Attempt))}
	if !op.DueAt.IsZero() && op.Type == "STEP" {
		retry.NextAttemptDelaySeconds = new(api.DurationSeconds(op.DueAt.Sub(event.At) / time.Second))
	}
	switch event.Type {
	case "ExecutionStarted":
		out.ExecutionStartedDetails = &api.ExecutionStartedDetails{ExecutionTimeout: new(api.DurationSeconds(execution.ExecutionTimeout)), Input: input}
	case "ExecutionSucceeded":
		out.ExecutionSucceededDetails = &api.ExecutionSucceededDetails{Result: result}
	case "ExecutionFailed":
		out.ExecutionFailedDetails = &api.ExecutionFailedDetails{Error: err}
	case "ExecutionStopped":
		out.ExecutionStoppedDetails = &api.ExecutionStoppedDetails{Error: err}
	case "ExecutionTimedOut":
		out.ExecutionTimedOutDetails = &api.ExecutionTimedOutDetails{Error: err}
	case "InvocationCompleted":
		out.Id = nil
		out.InvocationCompletedDetails = &api.InvocationCompletedDetails{RequestId: new(api.String(op.ID)), StartTimestamp: new(op.StartedAt), EndTimestamp: new(op.EndedAt)}
		if op.Error != nil {
			out.InvocationCompletedDetails.Error = err
		}
	case "StepStarted":
		out.StepStartedDetails = &api.StepStartedDetails{}
	case "StepSucceeded":
		out.StepSucceededDetails = &api.StepSucceededDetails{Result: result, RetryDetails: retry}
	case "StepFailed":
		out.StepFailedDetails = &api.StepFailedDetails{Error: err, RetryDetails: retry}
	case "ContextStarted":
		out.ContextStartedDetails = &api.ContextStartedDetails{}
	case "ContextSucceeded":
		out.ContextSucceededDetails = &api.ContextSucceededDetails{Result: result}
	case "ContextFailed":
		out.ContextFailedDetails = &api.ContextFailedDetails{Error: err}
	case "WaitStarted":
		out.WaitStartedDetails = &api.WaitStartedDetails{Duration: new(api.DurationSeconds(op.TimeoutSeconds)), ScheduledEndTimestamp: new(op.DueAt)}
	case "WaitSucceeded":
		out.WaitSucceededDetails = &api.WaitSucceededDetails{Duration: new(api.DurationSeconds(op.TimeoutSeconds))}
	case "WaitCancelled":
		out.WaitCancelledDetails = &api.WaitCancelledDetails{Error: err}
	case "CallbackStarted":
		out.CallbackStartedDetails = &api.CallbackStartedDetails{CallbackId: new(api.CallbackId(op.CallbackID)), Timeout: new(api.DurationSeconds(op.TimeoutSeconds)), HeartbeatTimeout: new(api.DurationSeconds(op.HeartbeatSeconds))}
	case "CallbackSucceeded":
		out.CallbackSucceededDetails = &api.CallbackSucceededDetails{Result: result}
	case "CallbackFailed":
		out.CallbackFailedDetails = &api.CallbackFailedDetails{Error: err}
	case "CallbackTimedOut":
		out.CallbackTimedOutDetails = &api.CallbackTimedOutDetails{Error: err}
	case "ChainedInvokeStarted":
		out.ChainedInvokeStartedDetails = &api.ChainedInvokeStartedDetails{FunctionName: new(api.NamespacedFunctionName(op.TargetFunction)), Input: input, TenantId: durableOptional[api.TenantId](op.TargetTenant)}
	case "ChainedInvokeSucceeded":
		out.ChainedInvokeSucceededDetails = &api.ChainedInvokeSucceededDetails{Result: result}
	case "ChainedInvokeFailed":
		out.ChainedInvokeFailedDetails = &api.ChainedInvokeFailedDetails{Error: err}
	case "ChainedInvokeStopped":
		out.ChainedInvokeStoppedDetails = &api.ChainedInvokeStoppedDetails{Error: err}
	case "ChainedInvokeTimedOut":
		out.ChainedInvokeTimedOutDetails = &api.ChainedInvokeTimedOutDetails{Error: err}
	}
	return out
}

// Runtime envelopes use Unix milliseconds, unlike the public REST JSON APIs,
// whose generated codecs own Smithy's Unix-second timestamp binding.
type durableRuntimeOperation struct {
	api.Operation
	StartTimestamp int64               `json:"StartTimestamp"`
	EndTimestamp   *int64              `json:"EndTimestamp,omitempty"`
	StepDetails    *durableRuntimeStep `json:"StepDetails,omitempty"`
	WaitDetails    *durableRuntimeWait `json:"WaitDetails,omitempty"`
}
type durableRuntimeStep struct {
	Attempt              int32                 `json:"Attempt"`
	Result               *api.OperationPayload `json:"Result,omitempty"`
	Error                *api.ErrorObject      `json:"Error,omitempty"`
	NextAttemptTimestamp *int64                `json:"NextAttemptTimestamp,omitempty"`
}
type durableRuntimeWait struct {
	ScheduledEndTimestamp *int64 `json:"ScheduledEndTimestamp,omitempty"`
}

func durableRuntimeOperations(v DurableExecutionRecord) []durableRuntimeOperation {
	operations := durableOperations(v.Operations)
	out := make([]durableRuntimeOperation, len(operations))
	for i, op := range operations {
		out[i] = durableRuntimeOperation{Operation: op, StartTimestamp: op.StartTimestamp.UnixMilli()}
		if op.EndTimestamp != nil {
			out[i].EndTimestamp = new(op.EndTimestamp.UnixMilli())
		}
		if op.StepDetails != nil {
			detail := op.StepDetails
			out[i].StepDetails = &durableRuntimeStep{Attempt: int32(*detail.Attempt), Result: detail.Result, Error: detail.Error}
			if detail.NextAttemptTimestamp != nil {
				out[i].StepDetails.NextAttemptTimestamp = new(detail.NextAttemptTimestamp.UnixMilli())
			}
		}
		if op.WaitDetails != nil {
			out[i].WaitDetails = &durableRuntimeWait{}
			if op.WaitDetails.ScheduledEndTimestamp != nil {
				out[i].WaitDetails.ScheduledEndTimestamp = new(op.WaitDetails.ScheduledEndTimestamp.UnixMilli())
			}
		}
	}
	return out
}
