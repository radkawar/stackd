package lambda

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type durableRuntimeKey struct{}

func isDurableRuntimeInvocation(ctx context.Context) bool {
	return ctx.Value(durableRuntimeKey{}) != nil
}

type durableKernel struct {
	mu     sync.Mutex
	notify chan struct{}
	active map[string]context.CancelFunc
}

func newDurableKernel(_ *Service) *durableKernel {
	return &durableKernel{notify: make(chan struct{}), active: map[string]context.CancelFunc{}}
}
func (k *durableKernel) changed() {
	k.mu.Lock()
	close(k.notify)
	k.notify = make(chan struct{})
	k.mu.Unlock()
}
func (k *durableKernel) changes() <-chan struct{} { k.mu.Lock(); defer k.mu.Unlock(); return k.notify }
func (k *durableKernel) stop(arn string) {
	k.mu.Lock()
	cancel := k.active[arn]
	k.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Service) startDurable(tx Transaction, function FunctionRecord, ref FunctionReference, name string, payload []byte, kind, clientContext, trace string) (DurableExecutionRecord, error) {
	var zero DurableExecutionRecord
	if ref.Qualifier == "" {
		return zero, durableParameter("Durable functions must be invoked with a version or alias qualifier.")
	}
	if function.State != "Active" {
		return zero, failure("ResourceConflictException", "Function is not active: "+function.State, 409)
	}
	if s.executor == nil || s.roles == nil {
		return zero, unsupported("No Lambda container executor is configured.")
	}
	if name == "" {
		name = uuid.NewString()
	}
	rows, err := tx.DurableExecutions()
	if err != nil {
		return zero, err
	}
	now := s.clock.Now()
	for _, v := range rows {
		if v.Function.Scope != function.Key.Scope || v.Name != name || (!v.ExpiresAt.IsZero() && !now.Before(v.ExpiresAt)) {
			continue
		}
		// Native Event invocations accept duplicate names, including a changed
		// payload, and retain the original execution. Synchronous starts expose
		// the documented payload conflict to the caller.
		if kind != "Event" {
			v, err = cryptDurableRecord(tx.Context(), v, true)
			if err != nil {
				return zero, err
			}
		}
		if kind != "Event" && (v.Input == nil || *v.Input != string(payload) || v.Function.FunctionKey != function.Key) {
			return zero, failure("DurableExecutionAlreadyStartedException", "A durable execution with this name already exists with different input.", 400)
		}
		return v, nil
	}
	id := uuid.NewString()
	v := DurableExecutionRecord{Name: name, ID: id, Function: FunctionVersionKey{FunctionKey: function.Key, Version: function.Version}, Status: "RUNNING", Input: new(string(payload)), StartedAt: now, ExecutionTimeout: int32(*function.Durable.ExecutionTimeout), RetentionDays: int32(*function.Durable.RetentionPeriodInDays), Token: durableToken(), Generation: 1, NextRunAt: now, InvocationType: kind, ClientContext: clientContext, TraceID: trace}
	v.ARN = v.Function.ARN() + "/durable-execution/" + name + "/" + id
	if err := bindDurableEncryption(tx.Context(), &v, function); err != nil {
		return zero, err
	}
	v.Deadline = now.Add(time.Duration(v.ExecutionTimeout) * time.Second)
	if kind == "RequestResponse" {
		v.Deadline = now.Add(time.Duration(min(v.ExecutionTimeout, int32(function.Timeout), 900)) * time.Second)
	}
	operation := DurableOperationRecord{ID: id, Name: name, Type: "EXECUTION", Status: "STARTED", StartedAt: now, Payload: cloneDurablePointer(v.Input)}
	v.Operations = []DurableOperationRecord{operation}
	durableEvent(&v, "ExecutionStarted", operation, now)
	if err := putPreparedDurable(tx, v); err != nil {
		return zero, err
	}
	return v, nil
}

func (s *Service) submitDurableInvocation(ctx context.Context, in *api.InvokeInput, stream *invocationStream, options invocationOptions) (*invocationOutput, *awswire.Error, bool) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire, true
	}
	var function FunctionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		function, err = selectFunction(r, ref, awsctx.FromContext(ctx).RequestID, 0)
		if err != nil {
			return err
		}
		if wire := s.authorizeInvocation(r, ref, function, options.URLAuthType); wire != nil {
			return wire
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err), true
	}
	if function.Durable == nil {
		if in.DurableExecutionName != nil {
			return nil, durableParameter("DurableExecutionName requires a durable function."), true
		}
		return nil, nil, false
	}
	if value(in.InvocationType) == "DryRun" {
		return nil, nil, false
	}
	if stream != nil {
		return nil, unsupported("Durable functions do not support response streaming."), true
	}
	kind := value(in.InvocationType)
	if kind == "" {
		kind = "RequestResponse"
	}
	payload := []byte(in.Payload)
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	limit := 6 << 20
	if kind == "Event" {
		limit = 1 << 20
	}
	if len(payload) > limit {
		return nil, failure("RequestTooLargeException", "Request payload exceeds the invocation limit.", 413), true
	}
	if !json.Valid(payload) {
		return nil, failure("InvalidRequestContentException", "Could not parse request body into JSON.", 400), true
	}
	clientContext := ""
	if in.ClientContext != nil {
		decoded, err := base64.StdEncoding.DecodeString(value(in.ClientContext))
		if err != nil || len(*in.ClientContext) > 3583 || !json.Valid(decoded) {
			return nil, failure("InvalidRequestContentException", "ClientContext must be base64-encoded JSON within the 3583-byte limit.", 400), true
		}
		clientContext = string(decoded)
	}
	prepared, rejected := s.prepareDurableStart(ctx, function, value(in.DurableExecutionName), kind)
	if rejected != nil {
		return nil, rejected, true
	}
	ctx = prepared
	defer clearDurableMaterial(ctx)
	var v DurableExecutionRecord
	err = s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		function, err = selectFunction(tx, ref, awsctx.FromContext(ctx).RequestID, 0)
		if err != nil {
			return err
		}
		if wire := s.authorizeInvocation(tx, ref, function, options.URLAuthType); wire != nil {
			return wire
		}
		if s.closed.Load() {
			return failure("ServiceException", "Lambda service is shutting down.", 503)
		}
		v, err = s.startDurable(tx, function, ref, value(in.DurableExecutionName), payload, kind, clientContext, options.TraceID)
		if err != nil {
			return err
		}
		if kind == "Event" {
			return s.recordCall(tx.Context(), "Invoke", in, durableInvocationOutput(v, 202), nil)
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err), true
	}
	s.jobs.Wake()
	if kind == "Event" {
		return durableInvocationOutput(v, 202), nil, true
	}
	out, wire := s.waitDurable(ctx, v.ARN)
	return out, wire, true
}

func durableInvocationOutput(v DurableExecutionRecord, status int32) *invocationOutput {
	out := &invocationOutput{InvokeOutput: api.InvokeOutput{StatusCode: new(api.Integer(status)), DurableExecutionArn: new(api.DurableExecutionArn(v.ARN)), ExecutedVersion: new(api.Version(versionName(v.Function.Version)))}}
	if status == 202 {
		return out
	}
	if v.Result != nil {
		out.Payload = api.Blob(*v.Result)
	}
	if v.Status != "SUCCEEDED" {
		out.FunctionError = new(api.String("Unhandled"))
		errorType, errorMessage := v.Status, "Durable execution "+v.Status
		var stack []string
		if v.Error != nil {
			errorType, errorMessage = value(v.Error.ErrorType), value(v.Error.ErrorMessage)
			for _, frame := range v.Error.StackTrace {
				stack = append(stack, string(frame))
			}
		}
		out.Payload, _ = json.Marshal(struct {
			ErrorType    string   `json:"errorType"`
			ErrorMessage string   `json:"errorMessage"`
			StackTrace   []string `json:"stackTrace,omitempty"`
		}{ErrorType: errorType, ErrorMessage: errorMessage, StackTrace: stack})
	}
	return out
}

func (s *Service) waitDurable(ctx context.Context, arn string) (*invocationOutput, *awswire.Error) {
	for {
		notify := s.durable.changes()
		var v DurableExecutionRecord
		err := s.repository.View(ctx, func(r Reader) error { var err error; v, err = readPreparedDurable(r, arn); return err })
		if err != nil {
			return nil, wireError(err)
		}
		if v.Status != "RUNNING" {
			return durableInvocationOutput(v, 200), nil
		}
		select {
		case <-notify:
		case <-ctx.Done():
			return nil, wireError(ctx.Err())
		case <-s.lifetime.Done():
			return nil, wireError(s.lifetime.Err())
		}
	}
}

// executeDurableAccepted converts already-authorized source/async admission into
// retained durable work. It releases compute while the SDK is suspended; source
// acknowledgement still waits for the complete durable outcome.
func (s *Service) executeDurableAccepted(ctx context.Context, slot *execution, function FunctionRecord, ref FunctionReference, payload []byte, clientContext, trace string, logTail bool, stream *invocationStream, respond func(*invocationOutput, *awswire.Error)) {
	s.releaseInvocation(function.Key, slot)
	slot.mu.Lock()
	s.releaseExecution(slot)
	slot.mu.Unlock()
	if stream != nil {
		respond(nil, unsupported("Durable functions do not support response streaming."))
		return
	}
	prepared, rejected := s.prepareDurableStart(ctx, function, "", "RequestResponse")
	if rejected != nil {
		respond(nil, rejected)
		return
	}
	ctx = prepared
	defer clearDurableMaterial(ctx)
	var v DurableExecutionRecord
	err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		v, err = s.startDurable(tx, function, ref, "", payload, "RequestResponse", clientContext, trace)
		return err
	})
	if err != nil {
		respond(nil, wireError(err))
		return
	}
	s.jobs.Wake()
	out, wire := s.waitDurable(ctx, v.ARN)
	respond(out, wire)
}

func (s *Service) recoverDurableExecutions() error {
	return s.repository.Update(s.lifetime, func(tx Transaction) error {
		rows, err := tx.DurableExecutions()
		if err != nil {
			return err
		}
		for _, v := range rows {
			if v.Status != "RUNNING" {
				continue
			}
			changed := v.Claimed
			if v.Claimed {
				v.Claimed = false
				v.Generation++
				v.Token = durableToken()
				v.NextRunAt = s.clock.Now()
			}
			for i := range v.Operations {
				op := &v.Operations[i]
				if op.Type == "CHAINED_INVOKE" && op.Status == "STARTED" && op.DueAt.IsZero() {
					op.DueAt = s.clock.Now()
					op.Generation++
					changed = true
				}
			}
			if changed {
				if err := tx.PutDurableExecution(v); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *Service) runDurable(v DurableExecutionRecord) {
	ctx, cancel := context.WithCancel(s.lifetime)
	s.durable.mu.Lock()
	s.durable.active[v.ARN] = cancel
	s.durable.mu.Unlock()
	defer func() { cancel(); s.durable.mu.Lock(); delete(s.durable.active, v.ARN); s.durable.mu.Unlock() }()
	ctx = context.WithValue(ctx, durableRuntimeKey{}, true)
	requestID := uuid.NewString()
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: v.Function.Partition, AccountID: v.Function.Account, Region: v.Function.Region, RequestID: requestID, TraceHeader: v.TraceID})
	prepared, rejected := s.prepareDurableContext(ctx, v.ARN, "", true)
	if rejected != nil {
		slog.Error("Lambda durable runtime decryption failed", "execution", v.ARN, "code", rejected.Code)
		return
	}
	ctx = prepared
	defer clearDurableMaterial(ctx)
	ref := FunctionReference{FunctionKey: v.Function.FunctionKey, Qualifier: versionName(v.Function.Version)}
	var function FunctionRecord
	var slot *execution
	s.mu.Lock()
	err := s.repository.View(ctx, func(r Reader) error {
		current, err := readPreparedDurable(r, v.ARN)
		if err != nil {
			return err
		}
		if current.Generation != v.Generation || current.Status != "RUNNING" {
			return context.Canceled
		}
		v = current
		function, err = loadFunction(r, ref)
		if err != nil {
			return err
		}
		if _, wire := s.admitInvocation(r, v.Function, ref); wire != nil {
			return wire
		}
		slot = s.invocationExecutionLocked(v.Function, ref)
		return nil
	})
	s.mu.Unlock()
	started := s.clock.Now()
	var result *invocationOutput
	if err == nil {
		envelope := struct {
			DurableExecutionArn   string
			CheckpointToken       string
			InitialExecutionState struct{ Operations []durableRuntimeOperation }
			UpdatedOperationIds   []string
		}{DurableExecutionArn: v.ARN, CheckpointToken: v.Token, UpdatedOperationIds: []string{}}
		envelope.InitialExecutionState.Operations = durableRuntimeOperations(v)
		for _, op := range v.Operations {
			if durableTerminal(op.Status) || op.Status == "READY" {
				envelope.UpdatedOperationIds = append(envelope.UpdatedOperationIds, op.ID)
			}
		}
		payload, marshalErr := json.Marshal(envelope)
		if marshalErr != nil {
			err = marshalErr
			s.releaseInvocation(function.Key, slot)
			slot.mu.Lock()
			s.releaseExecution(slot)
			slot.mu.Unlock()
		} else {
			s.execute(ctx, slot, function, ref, payload, v.ClientContext, v.TraceID, false, nil, func(out *invocationOutput, wire *awswire.Error) { result, rejected = out, wire })
		}
	}
	if s.lifetime.Err() != nil {
		return
	}
	if err != nil {
		rejected = wireError(err)
	}
	var response struct {
		Status string
		Result *string
		Error  *api.ErrorObject
	}
	if rejected == nil && result != nil && result.FunctionError == nil {
		if err := json.Unmarshal(result.Payload, &response); err != nil {
			response.Status = "FAILED"
			response.Error = &api.ErrorObject{ErrorType: new(api.ErrorType("InvalidDurableExecutionResponse")), ErrorMessage: new(api.ErrorMessage(err.Error()))}
		}
	}
	commitErr := s.repository.Update(context.WithoutCancel(ctx), func(tx Transaction) error {
		current, err := readPreparedDurable(tx, v.ARN)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Generation != v.Generation || current.Status != "RUNNING" {
			return nil
		}
		now := s.clock.Now()
		current.Claimed = false
		var invocationError *api.ErrorObject
		if rejected != nil {
			invocationError = &api.ErrorObject{ErrorType: new(api.ErrorType(rejected.Code)), ErrorMessage: new(api.ErrorMessage(rejected.Message))}
		} else if result != nil && result.FunctionError != nil {
			invocationError = &api.ErrorObject{}
			if err := json.Unmarshal(result.Payload, invocationError); err != nil {
				invocationError.ErrorType = new(api.ErrorType(value(result.FunctionError)))
				invocationError.ErrorData = new(api.ErrorData(string(result.Payload)))
			}
		}
		durableEvent(&current, "InvocationCompleted", DurableOperationRecord{ID: requestID, Type: "INVOCATION", StartedAt: started, EndedAt: now, Error: invocationError}, now)
		switch {
		case rejected != nil || result == nil || result.FunctionError != nil:
			current.NextRunAt = now.Add(time.Second)
		case response.Status == "PENDING":
			// Callback/timer progress committed while this invocation was running
			// leaves NextRunAt set and is not lost by suspension.
		case response.Status == "SUCCEEDED":
			completeDurable(&current, "SUCCEEDED", response.Result, nil, now)
		case response.Status == "FAILED":
			completeDurable(&current, "FAILED", nil, response.Error, now)
		default:
			completeDurable(&current, "FAILED", nil, &api.ErrorObject{ErrorType: new(api.ErrorType("InvalidDurableExecutionResponse")), ErrorMessage: new(api.ErrorMessage("The runtime returned an invalid durable execution status."))}, now)
		}
		return putPreparedDurable(tx, current)
	})
	if commitErr != nil {
		slog.Error("Lambda durable runtime result commit failed", "execution", v.ARN, "error", commitErr)
	}
	s.durable.changed()
	s.jobs.Wake()
}
