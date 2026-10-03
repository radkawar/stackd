package lambda

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	runtime "stackd/compute/lambda"
	"stackd/compute/lambda/managed"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type capacityLongInvocationKey struct{}

func withCapacityLongInvocation(ctx context.Context) context.Context {
	return context.WithValue(ctx, capacityLongInvocationKey{}, true)
}

func (s *Service) executeManagedAccepted(ctx context.Context, slot *execution, f FunctionRecord, ref FunctionReference, payload []byte, clientContext, traceID string, logTail bool, stream *invocationStream, respond func(*invocationOutput, *awswire.Error)) {
	// Managed environments multiplex their own requests; the ordinary exclusive
	// container slot is never held while the guest runs concurrent customer code.
	slot.mu.Lock()
	s.releaseExecution(slot)
	slot.mu.Unlock()
	var output *invocationOutput
	var rejected *awswire.Error
	defer func() { s.releaseInvocation(f.Key, slot); respond(output, rejected) }()
	if stream != nil {
		rejected = unsupported("Managed guest response streaming is not implemented.")
		return
	}
	if f.Version == 0 {
		rejected = capacityParameter("Managed instances cannot invoke the unpublished $LATEST configuration.")
		return
	}
	if f.State != "Active" {
		rejected = failure("ResourceConflictException", "Function is not active: "+f.State, 409)
		return
	}
	if s.capacityBackend == nil {
		rejected = unsupported("A real managed EC2 guest backend is required.")
		return
	}
	var provider CapacityProviderRecord
	var guests []CapacityGuestRecord
	var environments []CapacityEnvironmentRecord
	err := s.repository.View(ctx, func(r Reader) error {
		key, err := capacityKey(r.Context(), f.Capacity.ProviderARN)
		if err != nil {
			return err
		}
		provider, err = r.CapacityProvider(key)
		if err != nil {
			return err
		}
		if provider.State != "Active" {
			return failure("ResourceConflictException", "Capacity provider is not active.", 409)
		}
		current, err := loadDeployment(r, FunctionVersionKey{FunctionKey: f.Key, Version: f.Version})
		if err != nil {
			return err
		}
		if current.DeploymentRevision != f.DeploymentRevision {
			return failure("ResourceConflictException", "Managed deployment changed before routing.", 409)
		}
		scaling, err := effectiveCapacityScaling(r, current)
		if err != nil {
			return err
		}
		if scaling.MaxEnvironments == 0 {
			return failure("ResourceConflictException", "Managed function version is deactivated.", 409)
		}
		environments, err = r.CapacityEnvironments(FunctionVersionKey{FunctionKey: f.Key, Version: f.Version})
		if err != nil {
			return err
		}
		guests, err = r.CapacityGuests(key)
		return err
	})
	if err != nil {
		rejected = wireError(err)
		return
	}
	byGuest := map[string]CapacityGuestRecord{}
	for _, g := range guests {
		byGuest[g.ID] = g
	}
	invocation := runtime.Invocation{RequestID: awsctx.FromContext(ctx).RequestID, FunctionARN: ref.ARN(), Payload: payload, ClientContext: clientContext, TraceID: recursionTrace(traceID, f.Key, s.clock.Now())}
	if invocation.RequestID == "" {
		invocation.RequestID = uuid.NewString()
	}
	started := s.clock.Now()
	timeout := min(time.Duration(f.Timeout)*time.Second, 900*time.Second)
	if long, _ := ctx.Value(capacityLongInvocationKey{}).(bool); long {
		timeout = time.Duration(f.Timeout) * time.Second
	}
	for _, e := range environments {
		if e.State != "Ready" || e.Generation != f.DeploymentRevision || !s.clock.Now().Before(e.CredentialsExpire.Add(-time.Minute)) {
			continue
		}
		g, ok := byGuest[e.GuestID]
		if !ok || g.State != "Ready" {
			continue
		}
		client, err := s.capacityBackend.Client(capacityOwnerContext(ctx, provider.Key), provider, g)
		if err != nil {
			rejected = wireError(err)
			return
		}
		outcome, err := client.InvokeWithTimeout(ctx, e.ID, invocation, timeout)
		client.Close()
		var remote *managed.RemoteError
		if errors.As(err, &remote) && remote.Status == 429 {
			continue
		}
		if err != nil {
			rejected = wireError(err)
			return
		}
		output = &invocationOutput{InvokeOutput: api.InvokeOutput{StatusCode: new(api.Integer(200)), Payload: api.Blob(outcome.Result.Payload), ExecutedVersion: new(api.Version(versionName(f.Version)))}, runtimeContentType: outcome.Result.ContentType}
		if outcome.Result.FunctionError != "" {
			output.FunctionError = new(api.String(outcome.Result.FunctionError))
		}
		if logTail {
			output.LogResult = new(api.String(base64.StdEncoding.EncodeToString(outcome.Report.Logs)))
		}
		if err = s.repository.Update(context.WithoutCancel(ctx), func(tx Transaction) error {
			return s.stageExecutionMetrics(tx, ref, versionName(f.Version), started, outcome.Report)
		}); err != nil {
			slog.Error("Lambda managed execution metric commit failed", "function", f.Key.ARN(), "error", err)
		}
		s.jobs.Wake()
		return
	}
	rejected = failure("TooManyRequestsException", "No initialized managed execution environment has available concurrency.", 429)
}

func (s *Service) deployManagedUpdate(candidate FunctionRecord) {
	ctx, cancel := context.WithTimeout(ownerContext(s.lifetime, candidate.Key), 30*time.Second)
	defer cancel()
	var provider CapacityProviderRecord
	err := s.repository.View(ctx, func(r Reader) error {
		key, err := capacityKey(r.Context(), candidate.Capacity.ProviderARN)
		if err != nil {
			return err
		}
		provider, err = r.CapacityProvider(key)
		return err
	})
	if err == nil && s.capacityBackend == nil {
		err = unsupported("A managed EC2 guest backend is required.")
	}
	if err == nil {
		err = s.capacityBackend.Validate(ctx, provider)
	}
	commitErr := s.repository.Update(ctx, func(tx Transaction) error {
		pending, loadErr := tx.PendingFunction(candidate.Key)
		if loadErr != nil {
			return loadErr
		}
		if pending.DeploymentRevision != candidate.DeploymentRevision {
			return nil
		}
		current, loadErr := tx.Function(candidate.Key)
		if loadErr != nil {
			return loadErr
		}
		if err != nil {
			current.UpdateStatus = "Failed"
			current.UpdateReason = err.Error()
			if loadErr = tx.PutFunction(current); loadErr != nil {
				return loadErr
			}
		} else {
			pending.State = "Active"
			pending.StateReason = ""
			pending.StateReasonCode = ""
			pending.UpdateStatus = "Successful"
			pending.UpdateReason = ""
			pending.Revision = uuid.NewString()
			if loadErr = tx.PutFunction(pending); loadErr != nil {
				return loadErr
			}
		}
		// Managed published versions remain Pending until actual guest Runtime API
		// readiness. A configuration commit never publishes fictional warm capacity.
		return tx.DeletePendingFunction(candidate.Key)
	})
	if commitErr != nil && s.lifetime.Err() == nil {
		slog.Error("Lambda managed deployment commit failed", "function", candidate.Key.ARN(), "error", commitErr)
	}
	s.jobs.Wake()
}
