package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"log/slog"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
	"strings"
	"time"
)

// Events joins accepted invocation facts to the resource transaction.
type Events interface {
	AppendLambdaInvocationAccepted(context.Context, journal.Envelope, journal.LambdaInvocationAccepted) error
	AppendLambdaSourceBatchAccepted(context.Context, journal.Envelope, journal.LambdaSourceBatchAccepted) error
}

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

// Invoke enters the same authorization, audit and runtime path as the generated
// frontend. The returned request ID is the actual Lambda request/runtime ID;
// internal callers supply trusted request scope, not runtime behavior.
func (s *Service) Invoke(ctx context.Context, in *api.InvokeInput) (*api.InvokeOutput, string, *awswire.Error) {
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID = uuid.NewString()
	model, _ := awscatalog.LookupService("lambda")
	operation, _ := model.Operation("Invoke")
	out, rejected := s.ExecuteCommand(awsctx.WithMetadata(ctx, metadata), awsapi.DecodedRequest{Operation: operation, Input: in})
	if rejected != nil {
		return nil, metadata.RequestID, rejected
	}
	return out.(*api.InvokeOutput), metadata.RequestID, nil
}

// CheckInvoke performs the ordinary Invoke DryRun admission and records its
// outcome without accepting an event or starting a customer runtime.
func (s *Service) CheckInvoke(ctx context.Context, functionARN string) *awswire.Error {
	_, _, wire := s.Invoke(ctx, &api.InvokeInput{
		FunctionName:   new(api.NamespacedFunctionName(functionARN)),
		InvocationType: new(api.InvocationType("DryRun")),
	})
	return wire
}

type eventSourceARNKey struct{}

// InvokeEvent accepts an event under trusted request metadata supplied by an
// internal adapter. sourceARN is trusted invocation context, not caller identity.
// The returned request ID follows the accepted work into the real runtime.
// Nil error means durable acceptance, not successful customer code.
func (s *Service) InvokeEvent(ctx context.Context, functionARN string, payload []byte, sourceARN string) (string, *awswire.Error) {
	// Internal delivery is a new Lambda request; parent identity retains causality.
	if sourceARN != "" {
		ctx = context.WithValue(ctx, eventSourceARNKey{}, sourceARN)
	}
	_, requestID, wire := s.Invoke(ctx, &api.InvokeInput{
		FunctionName:   new(api.NamespacedFunctionName(functionARN)),
		InvocationType: new(api.InvocationType("Event")),
		Payload:        api.Blob(payload),
	})
	return requestID, wire
}
func (s *Service) acceptEvent(ctx context.Context, ref FunctionReference, payload []byte) *awswire.Error {
	return s.acceptEventWithOperation(ctx, ref, payload, "Invoke")
}

func (s *Service) acceptEventWithOperation(ctx context.Context, ref FunctionReference, payload []byte, operation string) *awswire.Error {
	if len(payload) > 1<<20 {
		return failure("RequestTooLargeException", "Asynchronous request payload exceeds 1 MB.", 413)
	}
	if !json.Valid(payload) {
		return failure("InvalidRequestContentException", "Could not parse request body into JSON.", 400)
	}
	closed := s.closed.Load()
	if closed {
		return failure("ServiceException", "Lambda service is shutting down.", 503)
	}
	key, arn := ref.FunctionKey, ref.ARN()
	err := s.repository.Update(ctx, func(tx Transaction) error {
		metadata := awsctx.FromContext(tx.Context())
		f, err := selectFunction(tx, ref, metadata.RequestID, 0)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(tx, "InvokeFunction", ref, f, nil); wire != nil {
			return wire
		}
		if s.executor == nil || s.roles == nil {
			return unsupported("No Lambda container executor is configured.")
		}
		if f.State != "Active" {
			return failure("ResourceConflictException", "Function is not active: "+f.State, 409)
		}
		settings, err := effectiveEventInvokeConfig(tx, eventInvokeConfigReference(ref))
		if err != nil {
			return err
		}
		now := s.clock.Now()
		v := InvocationRecord{ID: uuid.NewString(), Key: key, FunctionARN: arn, Payload: payload, RequestID: metadata.RequestID, ParentEventID: metadata.ParentEventID, TraceHeader: metadata.TraceHeader, Accepted: now, Due: now, Version: 1, State: "queued", Settings: settings, RoleARN: f.Role, DeadLetterARN: f.DeadLetterARN}
		if v.RequestID == "" {
			v.RequestID = v.ID
		}
		if err := tx.PutInvocation(v); err != nil {
			return err
		}
		if err := s.stageMetric(tx, ref, now, metricAsyncReceived, 1); err != nil {
			return err
		}
		if s.events != nil {
			if err := s.events.AppendLambdaInvocationAccepted(tx.Context(), apievents.WithOrigin(tx.Context(), journal.Envelope{At: now, Partition: key.Partition, AccountID: key.Account, Region: key.Region}), journal.LambdaInvocationAccepted{InvocationID: v.ID, FunctionARN: arn}); err != nil {
				return err
			}
		}
		if operation == "InvokeAsync" {
			return s.recordLegacyInvocation(tx.Context(), ref)
		}
		return s.recordInvocation(tx.Context(), "Invoke", &api.InvokeInput{FunctionName: new(api.NamespacedFunctionName(arn)), InvocationType: new(api.InvocationType("Event"))}, nil, versionName(f.Version))
	})
	if err != nil {
		return wireError(err)
	}
	s.jobs.Wake()
	return nil
}

// selectInvocation refreshes queue-owned controls only while the requested
// target exists. Deletion cannot erase an already accepted failure destination.
func selectInvocation(r Reader, v *InvocationRecord) (FunctionRecord, error) {
	ref := v.Reference()
	function, err := selectFunction(r, ref, v.RequestID, v.InvokeCount+v.SystemErrors)
	if err != nil {
		return FunctionRecord{}, err
	}
	settings, err := r.EventInvokeConfig(eventInvokeConfigReference(ref))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return FunctionRecord{}, err
	}
	if !v.SettingsDetached {
		v.Settings = defaultEventInvokeSettings()
		if err == nil {
			v.Settings = settings.Effective
		}
	} else if err == nil && settings.AppliesAt == nil {
		// Local configuration application is the representative transition,
		// not a claim about native API-readback convergence or an exact delay.
		v.Settings, v.SettingsDetached = settings.Effective, false
	}
	// Routing controls can remain detached across same-name recreation, but
	// execution and delivery authority always come from the selected deployment.
	// Published versions retain their own DLQ configuration after root updates.
	// TODO: Comeback calibrate mutable unqualified accepted-event DLQ updates.
	v.RoleARN, v.DeadLetterARN = function.Role, function.DeadLetterARN
	return function, nil
}

// missingAliasBeforeEntry is deliberately narrower than a missing deployment:
// native retry-enabled alias deletion dropped at age without a runtime entry or
// destination. Separate whole-function/fixed-version captures have 404 terminals;
// fixed-version/alias deletion after a real handler failure also has count2/404.
func missingAliasBeforeEntry(r Reader, v InvocationRecord) (bool, error) {
	ref := v.Reference()
	if v.Settings.MaxRetries == 0 || v.InvokeCount != 0 || ref.Qualifier == "" || ref.Qualifier[0] == '$' || strings.Trim(ref.Qualifier, "0123456789") == "" {
		return false, nil
	}
	if _, err := r.Function(ref.FunctionKey); err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	_, err := r.Alias(ref)
	if errors.Is(err, ErrNotFound) {
		return true, nil
	}
	return false, err
}

type invocationJobs struct{ s *Service }

func (j invocationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	s := j.s
	enabled := s.started.Load() && !s.closed.Load() && s.executor != nil && s.roles != nil
	if !enabled {
		return scheduler.Job{}, false, nil
	}
	var v scheduler.Job
	var found bool
	err := s.repository.View(ctx, func(r Reader) error { var err error; v, found, err = r.NextInvocation(); return err })
	return v, found, err
}
func (j invocationJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	s.mu.Lock()
	if !s.started.Load() || s.closed.Load() || s.executor == nil || s.roles == nil {
		s.mu.Unlock()
		return nil
	}
	s.work.Add(1)
	s.mu.Unlock()
	var claimed InvocationRecord
	launch := false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := tx.Invocation(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if v.Version != job.Version || v.State != "queued" || v.Due.After(s.clock.Now()) {
			return nil
		}
		if _, err := selectInvocation(tx, &v); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if condition := invocationCondition(v, s.clock.Now()); condition != "" {
			return s.completeInvocation(tx, v, condition, s.clock.Now())
		}
		v.State = "in-flight"
		v.Version++
		if err := tx.PutInvocation(v); err != nil {
			return err
		}
		claimed, launch = v, true
		return nil
	})
	if err != nil || !launch {
		s.work.Done()
		return err
	}
	// Never run or join customer code while holding the shared scheduler drain.
	go func() { defer s.work.Done(); s.runInvocation(claimed) }()
	return nil
}
func (s *Service) recoverInvocations() error {
	return s.repository.Update(s.lifetime, func(tx Transaction) error {
		rows, err := tx.InFlightInvocations()
		if err != nil {
			return err
		}
		for _, v := range rows {
			v.State = "queued"
			v.Version++
			v.Due = s.clock.Now()
			if err := tx.PutInvocation(v); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Service) runInvocation(v InvocationRecord) {
	ctx := awsctx.WithMetadata(s.lifetime, awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.Account, Region: v.Key.Region, RequestID: v.RequestID, ParentEventID: v.ParentEventID, TraceHeader: v.TraceHeader})
	var slot *execution
	var output *api.InvokeOutput
	var wire *awswire.Error
	var f FunctionRecord
	admitted, zero, resolved, missingAlias := false, false, false, false
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return
	}
	err := s.repository.View(ctx, func(r Reader) error {
		current, err := r.Invocation(v.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != v.Version || current.State != "in-flight" {
			return nil
		}
		f, err = selectInvocation(r, &v)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				var lookup error
				missingAlias, lookup = missingAliasBeforeEntry(r, v)
				if lookup != nil {
					return lookup
				}
			}
			return err
		}
		if invocationCondition(v, s.clock.Now()) != "" {
			return nil
		}
		resolved = true
		zero, wire = s.admitInvocation(r, FunctionVersionKey{FunctionKey: v.Key, Version: f.Version}, v.Reference())
		if wire != nil {
			return wire
		}
		admitted = true
		slot = s.invocationExecutionLocked(FunctionVersionKey{FunctionKey: v.Key, Version: f.Version}, v.Reference())
		return nil
	})
	s.mu.Unlock()
	if err != nil {
		wire = wireError(err)
	}
	if ctx.Err() == nil {
		if resolved {
			if err := s.recordExecution(ctx, v, f.Version, admitted); err != nil {
				wire = wireError(err)
			}
		} else if wire != nil && wire.Code == "ResourceNotFoundException" {
			if err := s.recordMissingInvocation(ctx, v); err != nil {
				wire = wireError(err)
			}
		}
	}
	if admitted {
		if wire == nil && ctx.Err() == nil {
			metadata := awsctx.FromContext(ctx)
			metadata.ParentEventID = ""
			if s.events != nil {
				metadata.ParentEventID = v.ID
			}
			response := make(chan executionResponse, 1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				s.execute(withCapacityLongInvocation(awsctx.WithMetadata(ctx, metadata)), slot, f, v.Reference(), v.Payload, "", v.TraceHeader, false, nil, func(output *invocationOutput, wire *awswire.Error) {
					response <- executionResponse{output: output, wire: wire}
				})
			}()
			// Successful destinations may precede extension completion. Failed
			// attempts must release their lease before making a retry runnable.
			defer func() { <-finished }()
			result := <-response
			wire = result.wire
			if result.output != nil {
				output = &result.output.InvokeOutput
			}
			if wire != nil || output.FunctionError != nil {
				<-finished
			}
		} else {
			s.releaseInvocation(v.Key, slot)
			slot.mu.Lock()
			s.releaseExecution(slot)
			slot.mu.Unlock()
		}
	}
	// Shutdown leaves the fenced claim for startup's legal at-least-once
	// recovery; a runtime may have completed before cancellation.
	if ctx.Err() != nil {
		return
	}
	for {
		err := s.finishInvocation(ctx, v, output, wire, zero, missingAlias)
		if err == nil {
			s.jobs.Wake()
			return
		}
		if ctx.Err() != nil {
			return
		}
		slog.Error("Lambda invocation completion commit failed", "invocation", v.ID, "error", err)
		timer := s.clock.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C():
		}
	}
}
func (s *Service) finishInvocation(ctx context.Context, selected InvocationRecord, output *api.InvokeOutput, wire *awswire.Error, zero, missingAlias bool) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Invocation(selected.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != selected.Version || current.State != "in-flight" {
			return nil
		}
		v := selected
		// Deletion/application may commit while customer code is running. Keep
		// that queue-control transition without replacing the real attempt result.
		v.SettingsDetached = current.SettingsDetached
		ref := v.Reference()
		now := s.clock.Now()
		if zero {
			return s.completeInvocation(tx, v, "ZeroReservedConcurrency", now)
		}
		if wire != nil && wire.Code == "RecursiveInvocationException" {
			v.ResponseStatus, v.ResponseError, v.ResponsePayload = 400, wire.Code, nil
			if err := s.stageMetric(tx, ref, now, "RecursiveInvocationsDropped", 1); err != nil {
				return err
			}
			return s.completeInvocation(tx, v, "RecursiveInvocation", now)
		}
		if wire != nil && wire.Code == "TooManyRequestsException" {
			// A service throttle is a real pre-execution response, not a handler
			// result. It replaces the previous response without a payload.
			v.ResponseStatus, v.ResponseVersion, v.ResponseError, v.ResponsePayload = 429, "", "", nil
			if err := s.stageThrottleMetrics(tx, ref, now); err != nil {
				return err
			}
		}
		if wire != nil && wire.Code == "ResourceNotFoundException" && !missingAlias {
			// async_deleted_targets_native.json measures retry0/count1 and
			// retry1/count2/status404 for queued whole/fixed targets, and count2
			// after fixed-version/alias handler failure. The 404 supersedes the
			// prior handler response; it is not another customer runtime entry.
			// TODO: Comeback resolve whole-function deletion after handler failure:
			// native metrics show an additional drop, but neither destination nor
			// DLQ through598s. Its scheduling/route fate is still unproven.
			v.InvokeCount++
			v.ResponseStatus, v.ResponseVersion, v.ResponseError, v.ResponsePayload = 404, "", "", nil
		}
		if output != nil {
			v.InvokeCount++
			v.ResponsePayload, v.ResponseError = []byte(output.Payload), value(output.FunctionError)
			v.ResponseVersion = value(output.ExecutedVersion)
			v.ResponseStatus = int(*output.StatusCode)
			// Queue age never turns a completed successful execution into failure.
			if v.ResponseError == "" {
				return s.completeInvocation(tx, v, "Success", now)
			}
		}
		if condition := invocationCondition(v, now); condition != "" {
			return s.completeInvocation(tx, v, condition, now)
		}
		var delay time.Duration
		if output == nil && (missingAlias || wire == nil || wire.Code != "ResourceNotFoundException") {
			// Missing alias lookup consumes no handler attempt or response. Its
			// retry uses the existing deterministic preparation-error backoff,
			// not a claim about native deleted-target scheduling intervals.
			// Other preparation failures also preserve the last real response.
			v.SystemErrors++
			delay = min(time.Second*time.Duration(1<<min(v.SystemErrors-1, 9)), 5*time.Minute)
		} else {
			delay = time.Minute * time.Duration(v.InvokeCount)
		}
		due := now.Add(delay)
		deadline := v.Accepted.Add(time.Duration(v.Settings.MaxAgeSeconds) * time.Second)
		if !due.Before(deadline) {
			if !missingAlias {
				return s.completeInvocation(tx, v, "EventAgeExceeded", now)
			}
			// Keep the event eligible for recreation until its actual deadline,
			// even when preparation-error backoff would cross it.
			due = deadline
		}
		v.State, v.Due = "queued", due
		v.Version++
		return tx.PutInvocation(v)
	})
}
