package lambda

import (
	"context"
	"time"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func callbackClosed(op DurableOperationRecord, now time.Time) bool {
	return durableTerminal(op.Status) || (!op.CallbackTimeoutAt.IsZero() && !now.Before(op.CallbackTimeoutAt)) || (!op.HeartbeatAt.IsZero() && !now.Before(op.HeartbeatAt))
}

func (s *Service) updateDurableCallback(ctx context.Context, id, action string, payload *string, callbackError *api.ErrorObject, input, output any) *awswire.Error {
	var arn string
	err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.DurableExecutions()
		if err != nil {
			return err
		}
		for _, v := range rows {
			if v.Function.Scope != scopeFor(ctx) {
				continue
			}
			for _, op := range v.Operations {
				if op.Type == "CALLBACK" && op.CallbackID == id {
					arn = v.ARN
					return nil
				}
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return wireError(err)
	}
	prepared, rejected := s.prepareDurableContext(ctx, arn, action, false)
	if rejected != nil {
		return rejected
	}
	ctx = prepared
	defer clearDurableMaterial(ctx)
	err = s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.authorizedDurable(tx, arn, action)
		if err != nil {
			return err
		}
		for i := range v.Operations {
			op := &v.Operations[i]
			if op.Type != "CALLBACK" || op.CallbackID != id {
				continue
			}
			now := s.clock.Now()
			if v.Status != "RUNNING" || callbackClosed(*op, now) {
				return failure("CallbackTimeoutException", "The callback has expired or has already been closed.", 400)
			}
			if action == "SendDurableExecutionCallbackHeartbeat" {
				if op.HeartbeatSeconds > 0 {
					op.HeartbeatAt = now.Add(time.Duration(op.HeartbeatSeconds) * time.Second)
				}
			} else {
				op.Status, op.Payload, op.Error, op.EndedAt = "SUCCEEDED", cloneDurablePointer(payload), cloneDurableError(callbackError), now
				kind := "CallbackSucceeded"
				if action == "SendDurableExecutionCallbackFailure" {
					op.Status, kind = "FAILED", "CallbackFailed"
				}
				op.Generation++
				durableEvent(&v, kind, *op, now)
				v.NextRunAt = now
			}
			if err := putPreparedDurable(tx, v); err != nil {
				return err
			}
			return s.recordCall(durableAuditContext(tx.Context(), v), action, input, output, nil)
		}
		return ErrNotFound
	})
	if err != nil {
		return wireError(err)
	}
	s.jobs.Wake()
	return nil
}

func (s *Service) durableCallbackSuccess(ctx context.Context, in *api.SendDurableExecutionCallbackSuccessInput) (*api.SendDurableExecutionCallbackSuccessOutput, *awswire.Error) {
	out := &api.SendDurableExecutionCallbackSuccessOutput{}
	if wire := s.updateDurableCallback(ctx, value(in.CallbackId), "SendDurableExecutionCallbackSuccess", new(string(in.Result)), nil, in, out); wire != nil {
		return nil, wire
	}
	return out, nil
}
func (s *Service) durableCallbackFailure(ctx context.Context, in *api.SendDurableExecutionCallbackFailureInput) (*api.SendDurableExecutionCallbackFailureOutput, *awswire.Error) {
	out := &api.SendDurableExecutionCallbackFailureOutput{}
	if wire := s.updateDurableCallback(ctx, value(in.CallbackId), "SendDurableExecutionCallbackFailure", nil, in.Error, in, out); wire != nil {
		return nil, wire
	}
	return out, nil
}
func (s *Service) durableCallbackHeartbeat(ctx context.Context, in *api.SendDurableExecutionCallbackHeartbeatInput) (*api.SendDurableExecutionCallbackHeartbeatOutput, *awswire.Error) {
	out := &api.SendDurableExecutionCallbackHeartbeatOutput{}
	if wire := s.updateDurableCallback(ctx, value(in.CallbackId), "SendDurableExecutionCallbackHeartbeat", nil, nil, in, out); wire != nil {
		return nil, wire
	}
	return out, nil
}
