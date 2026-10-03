package lambda

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type durableJobs struct{ s *Service }

func durableNextTime(v DurableExecutionRecord) time.Time {
	if v.Status != "RUNNING" {
		return v.ExpiresAt
	}
	due := v.Deadline
	consider := func(at time.Time) {
		if !at.IsZero() && (due.IsZero() || at.Before(due)) {
			due = at
		}
	}
	if !v.Claimed {
		consider(v.NextRunAt)
	}
	for _, op := range v.Operations {
		if durableTerminal(op.Status) {
			continue
		}
		switch op.Type {
		case "WAIT", "CHAINED_INVOKE":
			consider(op.DueAt)
		case "STEP":
			if op.Status == "PENDING" {
				consider(op.DueAt)
			}
		case "CALLBACK":
			consider(op.CallbackTimeoutAt)
			consider(op.HeartbeatAt)
		}
	}
	return due
}

func (j durableJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	s := j.s
	if !s.started.Load() || s.closed.Load() {
		return
	}
	err = s.repository.View(ctx, func(r Reader) error {
		rows, err := r.DurableExecutions()
		if err != nil {
			return err
		}
		for _, v := range rows {
			due := durableNextTime(v)
			if due.IsZero() {
				continue
			}
			candidate := scheduler.Job{Key: v.ARN, Due: due, Version: v.Generation}
			if !found || scheduler.Compare(candidate, job) < 0 {
				job, found = candidate, true
			}
		}
		return nil
	})
	return
}

func (j durableJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	var snapshot DurableExecutionRecord
	if err := s.repository.View(ctx, func(r Reader) error { var err error; snapshot, err = r.DurableExecution(job.Key); return err }); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	if snapshot.Generation != job.Version {
		return nil
	}
	if snapshot.Status == "RUNNING" {
		prepared, rejected := s.prepareDurableContext(ctx, job.Key, "", true)
		if rejected != nil {
			return rejected
		}
		ctx = prepared
		defer clearDurableMaterial(ctx)
	}
	s.mu.Lock()
	if s.closed.Load() || !s.started.Load() {
		s.mu.Unlock()
		return nil
	}
	s.work.Add(1)
	s.mu.Unlock()
	var launch *DurableExecutionRecord
	var chains []DurableOperationRecord
	var chainExecution DurableExecutionRecord
	var stop bool
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := tx.DurableExecution(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if v.Generation != job.Version {
			return nil
		}
		now := s.clock.Now()
		if v.Status != "RUNNING" {
			if !v.ExpiresAt.IsZero() && !now.Before(v.ExpiresAt) {
				return tx.DeleteDurableExecution(v.ARN)
			}
			return nil
		}
		v, err = cryptDurableRecord(ctx, v, true)
		if err != nil {
			return err
		}
		if !now.Before(v.Deadline) {
			completeDurable(&v, "TIMED_OUT", nil, &api.ErrorObject{ErrorType: new(api.ErrorType("DurableExecutionTimeout")), ErrorMessage: new(api.ErrorMessage("Durable execution exceeded its execution timeout."))}, now)
			stop = true
		} else {
			for i := range v.Operations {
				op := &v.Operations[i]
				if durableTerminal(op.Status) {
					continue
				}
				switch {
				case op.Type == "CHAINED_INVOKE" && !op.DueAt.IsZero() && !now.Before(op.DueAt):
					op.DueAt = time.Time{}
					op.Generation++
					chains = append(chains, *op)
				case op.Type == "CALLBACK" && callbackClosed(*op, now):
					op.Status, op.EndedAt = "TIMED_OUT", now
					op.Error = &api.ErrorObject{ErrorType: new(api.ErrorType("CallbackTimeout")), ErrorMessage: new(api.ErrorMessage("The callback timed out."))}
					durableEvent(&v, "CallbackTimedOut", *op, now)
					v.NextRunAt = now
				case op.Type == "WAIT" && !op.DueAt.IsZero() && !now.Before(op.DueAt):
					op.Status, op.EndedAt = "SUCCEEDED", now
					durableEvent(&v, "WaitSucceeded", *op, now)
					v.NextRunAt = now
				case op.Type == "STEP" && op.Status == "PENDING" && !now.Before(op.DueAt):
					op.Status = "READY"
					v.NextRunAt = now
				}
			}
			if !v.Claimed && !v.NextRunAt.IsZero() && !now.Before(v.NextRunAt) {
				v.Claimed = true
				v.NextRunAt = time.Time{}
				v.Generation++
				v.Token = durableToken()
				copy := v
				launch = &copy
			}
		}
		chainExecution = v
		return putPreparedDurable(tx, v)
	})
	if err != nil {
		s.work.Done()
		return err
	}
	if stop {
		s.durable.stop(job.Key)
	}
	s.durable.changed()
	if launch == nil && len(chains) == 0 {
		s.work.Done()
		return nil
	}
	// Each real effect is independently cancellable and outside the scheduler's
	// transaction/gate. A waiting chained function does not serialize siblings.
	go func() {
		defer s.work.Done()
		var work sync.WaitGroup
		for _, op := range chains {
			work.Add(1)
			go func() { defer work.Done(); s.runDurableChain(chainExecution, op) }()
		}
		if launch != nil {
			s.runDurable(*launch)
		}
		work.Wait()
	}()
	return nil
}

// durableRoleContext is implemented by the existing IAM/STS role adapter.
// It is not an ambient credential fallback or a second authority evaluator.
type durableRoleContext interface {
	DurableContext(context.Context, string, string, string) (context.Context, *awswire.Error)
}

func (s *Service) runDurableChain(v DurableExecutionRecord, op DurableOperationRecord) {
	ctx := ownerContext(s.lifetime, v.Function.FunctionKey)
	prepared, encryptionError := s.prepareDurableContext(ctx, v.ARN, "", true)
	if encryptionError != nil {
		slog.Error("Lambda durable chained decryption failed", "execution", v.ARN, "code", encryptionError.Code)
		return
	}
	ctx = prepared
	defer clearDurableMaterial(ctx)
	var function FunctionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		function, err = loadFunction(r, FunctionReference{FunctionKey: v.Function.FunctionKey, Qualifier: versionName(v.Function.Version)})
		return err
	})
	var result *api.InvokeOutput
	var rejected *awswire.Error
	if err != nil {
		rejected = wireError(err)
	} else if authority, ok := s.roles.(durableRoleContext); !ok {
		rejected = unsupported("Durable chained invocation role authority is not configured.")
	} else {
		ctx, rejected = authority.DurableContext(ctx, function.Role, function.Key.ARN(), function.Key.Name)
		if rejected == nil {
			ref, wire := parseFunctionReference(ctx, op.TargetFunction, "")
			if wire != nil {
				rejected = wire
			} else if ref.Account != v.Function.Account {
				rejected = durableParameter("Cross-account chained invocations are not supported.")
			} else {
				payload := api.Blob("null")
				if op.Payload != nil {
					payload = api.Blob(*op.Payload)
				}
				input := &api.InvokeInput{FunctionName: new(api.NamespacedFunctionName(op.TargetFunction)), Payload: payload, TenantId: durableOptional[api.TenantId](op.TargetTenant)}
				var target FunctionRecord
				if err := s.repository.View(ctx, func(r Reader) error { var err error; target, err = loadFunction(r, ref); return err }); err == nil && target.Durable != nil {
					input.DurableExecutionName = new(api.DurableExecutionName(uuid.NewSHA1(uuid.NameSpaceURL, []byte(v.ARN+"/"+op.ID)).String()))
				}
				metadata := awsctx.FromContext(ctx)
				metadata.TraceHeader = v.TraceID
				ctx = awsctx.WithMetadata(ctx, metadata)
				result, _, rejected = s.Invoke(ctx, input)
			}
		}
	}
	if s.lifetime.Err() != nil {
		return
	}
	err = s.repository.Update(context.WithoutCancel(ctx), func(tx Transaction) error {
		current, err := readPreparedDurable(tx, v.ARN)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		index := durableOperationIndex(&current, op.ID)
		if index < 0 || current.Status != "RUNNING" {
			return nil
		}
		target := &current.Operations[index]
		if target.Generation != op.Generation || target.Status != "STARTED" {
			return nil
		}
		now := s.clock.Now()
		target.EndedAt = now
		target.Status = "SUCCEEDED"
		if rejected != nil {
			target.Status = "FAILED"
			target.Error = &api.ErrorObject{ErrorType: new(api.ErrorType(rejected.Code)), ErrorMessage: new(api.ErrorMessage(rejected.Message))}
		} else if result.FunctionError != nil {
			target.Status = "FAILED"
			target.Error = &api.ErrorObject{ErrorType: new(api.ErrorType(value(result.FunctionError))), ErrorData: new(api.ErrorData(string(result.Payload)))}
		} else {
			target.Payload = new(string(result.Payload))
		}
		kind := "ChainedInvokeSucceeded"
		if target.Status == "FAILED" {
			kind = "ChainedInvokeFailed"
		}
		durableEvent(&current, kind, *target, now)
		current.NextRunAt = now
		return putPreparedDurable(tx, current)
	})
	if err != nil {
		slog.Error("Lambda durable chained result commit failed", "execution", v.ARN, "operation", op.ID, "error", err)
	}
	s.jobs.Wake()
}
