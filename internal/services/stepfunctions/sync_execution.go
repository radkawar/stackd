package stepfunctions

import (
	"context"
	"errors"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/stepfunctions"
)

// Admission commits before waiting. Cancellation only detaches this caller; the
// retained Express execution continues under the service scheduler and clock.
func (s *Service) startSyncExecution(ctx context.Context, in *api.StartSyncExecutionInput) (*api.StartSyncExecutionOutput, error) {
	if err := includedExecutionData(in.IncludedData); err != nil {
		return nil, err
	}
	var admitted ExecutionRecord
	var effects transitionEffects
	err := s.repository.Attempt(ctx, func(tx Transaction) error {
		effects = transitionEffects{}
		var err error
		admitted, err = s.admitExecution(tx, value(in.StateMachineArn), in.Name, in.Input, in.TraceHeader, true, value(in.IncludedData) == "METADATA_ONLY", &effects)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.applyEffects(effects)
	s.notify()
	execution, err := s.waitExecution(ctx, admitted.Key)
	if err != nil {
		return nil, err
	}
	defer s.encryption.releaseSynchronous(admitted.Key)
	if execution.Stopped == nil {
		return nil, errors.New("terminal execution has no stop time")
	}
	out := &api.StartSyncExecutionOutput{
		ExecutionArn: new(api.Arn(execution.Key.ARN)), StateMachineArn: new(api.Arn(execution.Machine.ARN())),
		Name: new(api.Name(execution.Name)), StartDate: controlTimestamp(execution.Started), StopDate: controlTimestamp(*execution.Stopped),
		Status: new(api.SyncExecutionStatus(execution.Status)), BillingDetails: new(expressBilling(execution)),
	}
	include := value(in.IncludedData) != "METADATA_ONLY"
	if include || execution.Encrypted == nil {
		out.InputDetails = &api.CloudWatchEventsExecutionDataDetails{Included: new(api.IncludedDetails(include))}
		out.OutputDetails = &api.CloudWatchEventsExecutionDataDetails{Included: new(api.IncludedDetails(include))}
	}
	if include {
		out.Input = new(api.SensitiveData(execution.Input))
		if execution.Status == "SUCCEEDED" {
			out.Output = new(api.SensitiveData(execution.Output))
		}
		if execution.Error != "" {
			out.Error = new(api.SensitiveError(execution.Error))
		}
		if execution.Cause != "" {
			out.Cause = new(api.SensitiveCause(execution.Cause))
		}
	}
	if execution.TraceHeader != "" {
		out.TraceHeader = new(api.TraceHeader(execution.TraceHeader))
	}
	// execute owns the reservation and rejected-call audit; this transaction owns
	// the successful response after the actual workflow outcome becomes known.
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	err = s.repository.Attempt(completion, func(tx Transaction) error {
		return s.recordCall(tx.Context(), "StartSyncExecution", in, out, nil)
	})
	return out, err
}

func (s *Service) waitExecution(ctx context.Context, key ExecutionKey) (ExecutionRecord, error) {
	for {
		// Subscribe before reading: a terminal commit between the read and select
		// must either be observed by the read or close this exact channel.
		s.mu.Lock()
		changed, closed := s.changed, s.closed
		s.mu.Unlock()
		if closed {
			return ExecutionRecord{}, context.Canceled
		}
		var execution ExecutionRecord
		err := s.repository.Update(ctx, func(r Transaction) error {
			var err error
			execution, _, err = s.retainedExecution(r, key)
			if err == nil && execution.Status != "RUNNING" && execution.Encrypted != nil {
				revision, readErr := r.Revision(RevisionKey{Scope: key.Scope, ID: execution.RevisionID})
				if readErr != nil {
					return readErr
				}
				execution, err = s.workflowReader(r, revision, revision.RoleARN).execution(execution)
			}
			return err
		})
		if err != nil {
			return ExecutionRecord{}, err
		}
		if execution.Status != "RUNNING" {
			return execution, nil
		}
		select {
		case <-ctx.Done():
			return ExecutionRecord{}, ctx.Err()
		case <-s.ctx.Done():
			return ExecutionRecord{}, s.ctx.Err()
		case <-changed:
		}
	}
}
