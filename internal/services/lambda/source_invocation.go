package lambda

import (
	"context"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type sourceInvocationResult struct {
	Output    *api.InvokeOutput
	Wire      *awswire.Error
	Accepted  bool
	EventID   string
	RequestID string
}

// invokeSourceBatch admits configured source work through the ordinary Lambda
// execution path. Source owners authorize reads; Lambda owns admission.
func (s *Service) invokeSourceBatch(ctx context.Context, mapping EventSourceMappingRecord, payload []byte, recordIDs []string, requestID string) sourceInvocationResult {
	if wire := checkSynchronousPayloadSize(payload); wire != nil {
		return sourceInvocationResult{Wire: wire}
	}
	if requestID == "" {
		requestID = uuid.NewString()
	}
	metadata := awsctx.Metadata{Partition: mapping.Key.Partition, AccountID: mapping.Key.Account, Region: mapping.Key.Region, RequestID: requestID,
		SourceIP: "lambda.amazonaws.com", UserAgent: "lambda.amazonaws.com",
		ServicePrincipal: awsctx.ServicePrincipal{Name: "lambda.amazonaws.com", SourceARN: mapping.Key.ARN(), Type: "AWSService"}}
	metadata.TraceHeader = awsctx.FromContext(ctx).TraceHeader
	ctx = awsctx.WithMetadata(ctx, metadata)
	if s.apiEvents != nil || s.events != nil {
		var err error
		ctx, err = apievents.Reserve(ctx)
		if err != nil {
			return sourceInvocationResult{Wire: wireError(err)}
		}
	}
	var function FunctionRecord
	var slot *execution
	admitted := false
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return sourceInvocationResult{Wire: failure("ServiceException", "Lambda service is shutting down.", 503)}
	}
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		function, err = selectFunction(r, mapping.Function, metadata.RequestID, 0)
		if err != nil {
			return err
		}
		if _, wire := s.admitInvocation(r, FunctionVersionKey{FunctionKey: mapping.Function.FunctionKey, Version: function.Version}, mapping.Function); wire != nil {
			return wire
		}
		admitted = true
		slot = s.invocationExecutionLocked(FunctionVersionKey{FunctionKey: mapping.Function.FunctionKey, Version: function.Version}, mapping.Function)
		slot.image = function.Image
		return nil
	})
	var wire *awswire.Error
	if err != nil {
		wire = wireError(err)
	}
	if ctx.Err() == nil || admitted {
		completion, cancel := apievents.CompletionContext(ctx)
		if recordErr := s.recordSourceBatchInvocation(completion, mapping, function, recordIDs, wire); recordErr != nil {
			err = recordErr
		}
		cancel()
	}
	if err == nil {
		// Close cannot begin waiting between admission and work registration.
		s.work.Add(1)
	}
	s.mu.Unlock()
	if err != nil {
		if admitted {
			s.releaseInvocation(mapping.Function.FunctionKey, slot)
			slot.mu.Lock()
			s.releaseExecution(slot)
			slot.mu.Unlock()
		}
		if wire != nil && wire.Code == "RecursiveInvocationException" {
			if recordErr := s.repository.Update(context.WithoutCancel(ctx), func(tx Transaction) error {
				return s.stageMetric(tx, mapping.Function, s.clock.Now(), "RecursiveInvocationsDropped", 1)
			}); recordErr != nil {
				return sourceInvocationResult{Wire: wireError(recordErr)}
			}
			s.jobs.Wake()
		}
		if wire != nil && wire.Code == "TooManyRequestsException" {
			s.jobs.Wake()
		}
		return sourceInvocationResult{Wire: wireError(err)}
	}
	metadata.ParentEventID = apievents.EventID(ctx)
	executionContext := awsctx.WithMetadata(context.WithoutCancel(ctx), metadata)
	if mapping.Settings.MQ == nil && mapping.Settings.DocumentDB == nil {
		executionContext = withCapacityLongInvocation(executionContext)
	}
	response := make(chan executionResponse, 1)
	go func() {
		defer s.work.Done()
		s.execute(executionContext, slot, function, mapping.Function, payload, "", metadata.TraceHeader, false, nil, func(output *invocationOutput, wire *awswire.Error) {
			response <- executionResponse{output: output, wire: wire}
		})
	}()
	// Disable/delete cancels polling, not an accepted function invocation. Its
	// eventual result still belongs to the source's acknowledgement/checkpoint owner.
	result := <-response
	if result.wire != nil {
		return sourceInvocationResult{Wire: result.wire, Accepted: true, EventID: metadata.ParentEventID, RequestID: metadata.RequestID}
	}
	return sourceInvocationResult{Output: &result.output.InvokeOutput, Accepted: true, EventID: metadata.ParentEventID, RequestID: metadata.RequestID}
}
