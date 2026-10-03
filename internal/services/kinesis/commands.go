package kinesis

import (
	"context"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
)

type callContextKey struct{}

type callContext struct {
	action   string
	at       time.Time
	resource ResourceKey
	stream   *StreamRecord
	samples  []MetricSample
	admitted bool
}

func (s *Service) withCall(ctx context.Context, action string) context.Context {
	return context.WithValue(ctx, callContextKey{}, &callContext{action: action, at: s.clock.Now()})
}

func currentCall(ctx context.Context) *callContext {
	call, _ := ctx.Value(callContextKey{}).(*callContext)
	return call
}

func rememberResource(ctx context.Context, action string, key ResourceKey) {
	if call := currentCall(ctx); call != nil && call.action == action {
		call.resource = key
	}
}

func rememberStream(ctx context.Context, stream StreamRecord) {
	if call := currentCall(ctx); call != nil {
		call.stream = &stream
		call.resource = ResourceKey{Scope: stream.Key.Scope, ARN: stream.Key.ARN()}
	}
}

func runCommand[I, O any](s *Service, ctx context.Context, action string, in *I, fn func(context.Context, Transaction, *I) (*O, error)) (*O, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	ctx = s.withCall(ctx, action)
	var out *O
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		var err error
		out, err = fn(tx.Context(), tx, in)
		if err != nil {
			return err
		}
		return s.recordCall(tx.Context(), action, in, out, nil)
	})
	if err == nil {
		s.engines.wake()
		s.jobs.Wake()
		return out, nil
	}
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	if err := s.recordCall(completion, action, in, nil, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}

func runExternal[I, O any](s *Service, ctx context.Context, action string, in *I, fn func(context.Context, *I) (*O, error)) (*O, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	ctx = s.withCall(ctx, action)
	out, err := fn(ctx, in)
	s.completeDataMetrics(ctx, err)
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	err = s.repository.Update(completion, func(tx Transaction) error {
		if call := currentCall(ctx); call.stream != nil && len(call.samples) > 0 {
			key := MetricPublicationKey{Stream: call.stream.Key, Minute: s.clock.Now().UTC().Truncate(time.Minute)}
			if err := tx.AddMetricSamples(key, call.samples); err != nil {
				return err
			}
		}
		return s.recordCall(tx.Context(), action, in, out, rejected)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, rejected
}

// DescribeStream is the same authorized, audited command used by clients.
func (s *Service) DescribeStream(ctx context.Context, in *api.DescribeStreamInput) (*api.DescribeStreamOutput, *awswire.Error) {
	return runCommand(s, ctx, "DescribeStream", in, s.describeStream)
}

func (s *Service) PutRecord(ctx context.Context, in *api.PutRecordInput) (*api.PutRecordOutput, *awswire.Error) {
	return runExternal(s, ctx, "PutRecord", in, s.putRecord)
}

func (s *Service) PutRecords(ctx context.Context, in *api.PutRecordsInput) (*api.PutRecordsOutput, *awswire.Error) {
	return runExternal(s, ctx, "PutRecords", in, s.putRecords)
}

func (s *Service) GetShardIterator(ctx context.Context, in *api.GetShardIteratorInput) (*api.GetShardIteratorOutput, *awswire.Error) {
	return runExternal(s, ctx, "GetShardIterator", in, s.getShardIterator)
}

func (s *Service) GetRecords(ctx context.Context, in *api.GetRecordsInput) (*api.GetRecordsOutput, *awswire.Error) {
	return runExternal(s, ctx, "GetRecords", in, s.getRecords)
}

func (s *Service) ListShards(ctx context.Context, in *api.ListShardsInput) (*api.ListShardsOutput, *awswire.Error) {
	return runCommand(s, ctx, "ListShards", in, s.listShards)
}
