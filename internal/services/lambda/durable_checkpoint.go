package lambda

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func durableToken() string {
	var token [32]byte
	_, _ = rand.Read(token[:])
	return base64.StdEncoding.EncodeToString(token[:])
}

func durableParameter(message string) *awswire.Error {
	return failure("InvalidParameterValueException", message, 400)
}

func (s *Service) checkpointDurableExecution(ctx context.Context, in *api.CheckpointDurableExecutionInput) (*api.CheckpointDurableExecutionOutput, *awswire.Error) {
	prepared, rejected := s.prepareDurableContext(ctx, value(in.DurableExecutionArn), "CheckpointDurableExecution", false)
	if rejected != nil {
		return nil, rejected
	}
	ctx = prepared
	defer clearDurableMaterial(ctx)
	var out *api.CheckpointDurableExecutionOutput
	request, err := json.Marshal(in.Updates)
	if err != nil {
		return nil, wireError(err)
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.authorizedDurable(tx, value(in.DurableExecutionArn), "CheckpointDurableExecution")
		if err != nil {
			return err
		}
		now := s.clock.Now()
		for _, previous := range v.Checkpoints {
			if value(in.ClientToken) != "" && previous.ClientToken == value(in.ClientToken) && now.Before(previous.ExpiresAt) {
				if previous.PreviousToken != value(in.CheckpointToken) || !bytes.Equal(previous.Request, request) {
					return durableParameter("ClientToken was already used with different checkpoint parameters.")
				}
				out = &api.CheckpointDurableExecutionOutput{CheckpointToken: new(api.CheckpointToken(previous.NextToken)), NewExecutionState: &api.CheckpointUpdatedExecutionState{Operations: durableOperations(previous.Operations)}}
				return nil
			}
		}
		if v.Status != "RUNNING" || v.Token != value(in.CheckpointToken) {
			return durableParameter("The checkpoint token is invalid or the durable execution is no longer running.")
		}
		for _, update := range in.Updates {
			if err := applyDurableUpdate(&v, update, now); err != nil {
				return err
			}
		}
		oldToken := v.Token
		v.Token = durableToken()
		v.Checkpoints = slices.DeleteFunc(v.Checkpoints, func(c DurableCheckpointRecord) bool { return !now.Before(c.ExpiresAt) })
		if value(in.ClientToken) != "" {
			snapshot := make([]DurableOperationRecord, len(v.Operations))
			for i := range v.Operations {
				snapshot[i] = cloneDurableOperation(v.Operations[i])
			}
			v.Checkpoints = append(v.Checkpoints, DurableCheckpointRecord{ClientToken: value(in.ClientToken), PreviousToken: oldToken, NextToken: v.Token, Request: request, ExpiresAt: now.Add(15 * time.Minute), Operations: snapshot})
		}
		if err := putPreparedDurable(tx, v); err != nil {
			return err
		}
		out = &api.CheckpointDurableExecutionOutput{CheckpointToken: new(api.CheckpointToken(v.Token)), NewExecutionState: &api.CheckpointUpdatedExecutionState{Operations: durableOperations(v.Operations)}}
		return s.recordCall(tx.Context(), "CheckpointDurableExecution", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func durableOperationIndex(v *DurableExecutionRecord, id string) int {
	return slices.IndexFunc(v.Operations, func(o DurableOperationRecord) bool { return o.ID == id })
}

func durableEvent(v *DurableExecutionRecord, kind string, op DurableOperationRecord, at time.Time) {
	v.History = append(v.History, DurableEventRecord{ID: int32(len(v.History) + 1), At: at, Type: kind, Operation: cloneDurableOperation(op)})
}

func durableTerminal(status string) bool {
	return status == "SUCCEEDED" || status == "FAILED" || status == "STOPPED" || status == "TIMED_OUT" || status == "CANCELLED"
}

func completeDurable(v *DurableExecutionRecord, status string, result *string, err *api.ErrorObject, now time.Time) {
	if v.Status != "RUNNING" {
		return
	}
	v.Status, v.Result, v.Error, v.EndedAt = status, cloneDurablePointer(result), cloneDurableError(err), now
	v.NextRunAt = time.Time{}
	v.ExpiresAt = now.Add(time.Duration(v.RetentionDays) * 24 * time.Hour)
	v.Generation++
	v.Token = durableToken()
	index := durableOperationIndex(v, v.ID)
	if index >= 0 {
		op := &v.Operations[index]
		op.Status, op.Payload, op.Error, op.EndedAt = status, cloneDurablePointer(result), cloneDurableError(err), now
		event := map[string]string{"SUCCEEDED": "ExecutionSucceeded", "FAILED": "ExecutionFailed", "STOPPED": "ExecutionStopped", "TIMED_OUT": "ExecutionTimedOut"}[status]
		durableEvent(v, event, *op, now)
	}
}

func applyDurableUpdate(v *DurableExecutionRecord, update api.OperationUpdate, now time.Time) error {
	id, kind, action := value(update.Id), value(update.Type), value(update.Action)
	if kind == "EXECUTION" {
		if action != "SUCCEED" && action != "FAIL" {
			return durableParameter("EXECUTION updates must complete or fail the execution.")
		}
		status := "SUCCEEDED"
		if action == "FAIL" {
			status = "FAILED"
		}
		var payload *string
		if update.Payload != nil {
			payload = new(string(*update.Payload))
		}
		completeDurable(v, status, payload, update.Error, now)
		return nil
	}
	if kind != "STEP" && kind != "WAIT" && kind != "CALLBACK" && kind != "CONTEXT" && kind != "CHAINED_INVOKE" {
		return durableParameter("Unsupported durable operation type.")
	}
	if update.Payload != nil && len(*update.Payload) > 256*1024 && kind != "CHAINED_INVOKE" {
		return durableParameter("Operation payload exceeds 256 KB.")
	}
	index := durableOperationIndex(v, id)
	if index < 0 {
		if action != "START" {
			return durableParameter("The operation has not been started.")
		}
		if parent := value(update.ParentId); parent != "" && durableOperationIndex(v, parent) < 0 {
			return durableParameter("The parent operation does not exist.")
		}
		v.Operations = append(v.Operations, DurableOperationRecord{ID: id, ParentID: value(update.ParentId), Name: value(update.Name), Type: kind, SubType: value(update.SubType), StartedAt: now})
		index = len(v.Operations) - 1
	}
	op := &v.Operations[index]
	if op.Type != kind || (value(update.ParentId) != "" && op.ParentID != value(update.ParentId)) {
		return durableParameter("Operation identity does not match its checkpoint.")
	}
	if durableTerminal(op.Status) {
		return durableParameter("The operation is already closed.")
	}
	op.Generation++
	switch action {
	case "START":
		if op.Status != "" && op.Status != "READY" && op.Status != "STARTED" {
			return durableParameter("Operation is not ready to start.")
		}
		op.Status = "STARTED"
		switch kind {
		case "STEP":
			durableEvent(v, "StepStarted", *op, now)
		case "CONTEXT":
			if update.ContextOptions != nil && update.ContextOptions.ReplayChildren != nil {
				op.ReplayChildren = bool(*update.ContextOptions.ReplayChildren)
			}
			durableEvent(v, "ContextStarted", *op, now)
		case "WAIT":
			if update.WaitOptions == nil || update.WaitOptions.WaitSeconds == nil {
				return durableParameter("WAIT requires WaitOptions.WaitSeconds.")
			}
			op.TimeoutSeconds = int32(*update.WaitOptions.WaitSeconds)
			op.DueAt = now.Add(time.Duration(op.TimeoutSeconds) * time.Second)
			durableEvent(v, "WaitStarted", *op, now)
		case "CALLBACK":
			op.CallbackID = durableToken()
			if update.CallbackOptions != nil {
				if update.CallbackOptions.TimeoutSeconds != nil {
					op.TimeoutSeconds = int32(*update.CallbackOptions.TimeoutSeconds)
				}
				if update.CallbackOptions.HeartbeatTimeoutSeconds != nil {
					op.HeartbeatSeconds = int32(*update.CallbackOptions.HeartbeatTimeoutSeconds)
				}
			}
			if op.TimeoutSeconds > 0 {
				op.CallbackTimeoutAt = now.Add(time.Duration(op.TimeoutSeconds) * time.Second)
			}
			if op.HeartbeatSeconds > 0 {
				op.HeartbeatAt = now.Add(time.Duration(op.HeartbeatSeconds) * time.Second)
			}
			durableEvent(v, "CallbackStarted", *op, now)
		case "CHAINED_INVOKE":
			if update.ChainedInvokeOptions == nil {
				return durableParameter("CHAINED_INVOKE requires ChainedInvokeOptions.")
			}
			op.TargetFunction, op.TargetTenant = value(update.ChainedInvokeOptions.FunctionName), value(update.ChainedInvokeOptions.TenantId)
			if update.Payload != nil {
				op.Payload = new(string(*update.Payload))
			}
			op.DueAt = now
			durableEvent(v, "ChainedInvokeStarted", *op, now)
		}
	case "SUCCEED", "FAIL":
		if kind != "STEP" && kind != "CONTEXT" {
			return durableParameter("This operation is completed by the service, not by checkpoint updates.")
		}
		op.EndedAt, op.Error = now, cloneDurableError(update.Error)
		if update.Payload != nil {
			op.Payload = new(string(*update.Payload))
		}
		suffix := "Succeeded"
		op.Status = "SUCCEEDED"
		if action == "FAIL" {
			op.Status, suffix = "FAILED", "Failed"
		}
		prefix := "Step"
		if kind == "CONTEXT" {
			prefix = "Context"
		} else {
			op.Attempt++
		}
		durableEvent(v, prefix+suffix, *op, now)
	case "RETRY":
		if kind != "STEP" || update.StepOptions == nil || update.StepOptions.NextAttemptDelaySeconds == nil {
			return durableParameter("RETRY requires STEP and NextAttemptDelaySeconds.")
		}
		op.Attempt++
		op.Status, op.Error = "PENDING", cloneDurableError(update.Error)
		op.DueAt = now.Add(time.Duration(*update.StepOptions.NextAttemptDelaySeconds) * time.Second)
		durableEvent(v, "StepFailed", *op, now)
	case "CANCEL":
		if kind != "WAIT" {
			return durableParameter("Only WAIT operations may be cancelled.")
		}
		op.Status, op.EndedAt, op.Error = "CANCELLED", now, cloneDurableError(update.Error)
		durableEvent(v, "WaitCancelled", *op, now)
	default:
		return durableParameter("Invalid durable operation action.")
	}
	return nil
}
