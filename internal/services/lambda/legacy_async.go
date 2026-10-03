package lambda

import (
	"context"
	"encoding/json"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// invokeAsync retains the legacy payload and tracing boundary, while sharing
// durable acceptance, current InvokeFunction authority and real execution.
func (s *Service) invokeAsync(ctx context.Context, in *api.InvokeAsyncInput) (*api.InvokeAsyncOutput, *awswire.Error) {
	if len(in.InvokeArgs) > 256<<10 {
		return nil, failure("RequestEntityTooLargeException", "Request payload size exceeds the 256 KB InvokeAsync limit.", 413)
	}
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	metadata := awsctx.FromContext(ctx)
	metadata.TraceHeader = ""
	ctx = awsctx.WithMetadata(ctx, metadata)
	if wire := s.acceptEventWithOperation(ctx, ref, in.InvokeArgs, "InvokeAsync"); wire != nil {
		return nil, wire
	}
	return &api.InvokeAsyncOutput{Status: new(api.HttpStatus(202))}, nil
}

func (s *Service) recordLegacyInvocation(ctx context.Context, ref FunctionReference) error {
	if s.apiEvents == nil {
		return nil
	}
	call, err := projectLambdaCall(ctx, "InvokeAsync", &api.InvokeAsyncInput{FunctionName: new(api.NamespacedFunctionName(ref.ARN()))}, nil, nil)
	if err != nil {
		return err
	}
	call.RequestParameters, err = json.Marshal(map[string]string{"functionName": ref.ARN()})
	if err != nil {
		return err
	}
	call.EventResources = invocationResources(ref.FunctionKey)
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: ref.Partition, AccountID: ref.Account, Region: ref.Region}, call)
}
