package lambda

import (
	"context"
	"encoding/json"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/lambda"
	"stackd/journal"
)

// Management, checkpoint and callback classifications are pinned by the native
// captures. durable_audit_final additionally proves successful Stop and callback
// failure as Data events, including their function resource and version fields.
func durableAuditProjection(name string) (apievents.Projection, bool) {
	projection := apievents.Projection{EventName: name, Request: durableRequestProjection}
	switch name {
	case "GetDurableExecution", "GetDurableExecutionHistory", "ListDurableExecutionsByFunction":
		projection.Category, projection.ReadOnly = journal.CategoryManagement, true
	case "CheckpointDurableExecution":
		projection.Category = journal.CategoryData
		projection.Response = &durableCheckpointResponseProjection
	case "SendDurableExecutionCallbackSuccess", "SendDurableExecutionCallbackFailure", "SendDurableExecutionCallbackHeartbeat":
		projection.Category = journal.CategoryData
	case "StopDurableExecution":
		projection.Category = journal.CategoryData
		projection.Response = &awsapi.DocumentProjection{}
	case "GetDurableExecutionState":
		projection.Category, projection.ReadOnly = journal.CategoryData, true
	default:
		return projection, false
	}
	return projection, true
}

var durableRequestProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"CheckpointToken": {Mode: awsapi.OmitField},
	"ClientToken":     {Mode: awsapi.OmitField},
	"Updates.Payload": {Mode: awsapi.OmitField},
	"Updates.Error":   {Mode: awsapi.OmitField},
	"CallbackId":      {Mode: awsapi.OmitField},
	"Result":          {Mode: awsapi.OmitField},
	"Error":           {Mode: awsapi.RedactValueField},
}}

var durableCheckpointResponseProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"CheckpointToken": {Mode: awsapi.OmitField},
	"NewExecutionState.Operations.ExecutionDetails.InputPayload": {Mode: awsapi.OmitField},
	"NewExecutionState.Operations.StepDetails.Result":            {Mode: awsapi.OmitField},
	"NewExecutionState.Operations.StepDetails.Error":             {Mode: awsapi.OmitField},
	"NewExecutionState.Operations.ContextDetails.Result":         {Mode: awsapi.OmitField},
	"NewExecutionState.Operations.ContextDetails.Error":          {Mode: awsapi.OmitField},
	"NewExecutionState.Operations.CallbackDetails.CallbackId":    {Mode: awsapi.OmitField},
	"NewExecutionState.Operations.CallbackDetails.Result":        {Mode: awsapi.OmitField},
	"NewExecutionState.Operations.CallbackDetails.Error":         {Mode: awsapi.OmitField},
	"NewExecutionState.Operations.ChainedInvokeDetails.Result":   {Mode: awsapi.OmitField},
	"NewExecutionState.Operations.ChainedInvokeDetails.Error":    {Mode: awsapi.OmitField},
}}

type durableAuditExecutionKey struct{}

func durableAuditContext(ctx context.Context, execution DurableExecutionRecord) context.Context {
	return context.WithValue(ctx, durableAuditExecutionKey{}, execution.Function)
}

func projectDurableAudit(ctx context.Context, input any, call *journal.APICallCompleted) {
	var execution string
	var function FunctionVersionKey
	management := false
	switch input := input.(type) {
	case *api.GetDurableExecutionInput:
		execution, management = value(input.DurableExecutionArn), true
	case *api.GetDurableExecutionHistoryInput:
		execution, management = value(input.DurableExecutionArn), true
	case *api.CheckpointDurableExecutionInput:
		execution = value(input.DurableExecutionArn)
	case *api.GetDurableExecutionStateInput:
		execution = value(input.DurableExecutionArn)
	case *api.StopDurableExecutionInput:
		execution = value(input.DurableExecutionArn)
	case *api.SendDurableExecutionCallbackSuccessInput, *api.SendDurableExecutionCallbackFailureInput, *api.SendDurableExecutionCallbackHeartbeatInput:
		var ok bool
		function, ok = ctx.Value(durableAuditExecutionKey{}).(FunctionVersionKey)
		if !ok {
			return
		}
	default:
		return
	}
	if management {
		if execution != "" {
			call.EventResources = []journal.APIEventResource{{AccountID: scopeFor(ctx).Account, Type: "function", ARN: execution}}
		}
		return
	}
	version := function.ARN()
	if execution != "" {
		prefix, _, ok := strings.Cut(execution, "/durable-execution/")
		if !ok {
			return
		}
		ref, rejected := parseFunctionReference(ctx, prefix, "")
		if rejected != nil {
			return
		}
		function.FunctionKey = ref.FunctionKey
		version = prefix
	}
	call.EventResources = invocationResources(function.FunctionKey)
	call.AdditionalEventData, _ = json.Marshal(map[string]string{"functionVersion": version})
}
