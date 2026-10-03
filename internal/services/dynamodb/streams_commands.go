package dynamodb

import (
	"context"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/dynamodbstreams"
	"stackd/internal/awswire"
)

// ListStreams lists scoped generations using the caller's current permissions.
func (p *Streams) ListStreams(ctx context.Context, in *api.ListStreamsInput) (*api.ListStreamsOutput, *awswire.Error) {
	return runStreamCommand(p, ctx, "ListStreams", in, p.list)
}

// DescribeStream returns the retained generation and shard topology.
func (p *Streams) DescribeStream(ctx context.Context, in *api.DescribeStreamInput) (*api.DescribeStreamOutput, *awswire.Error) {
	return runStreamCommand(p, ctx, "DescribeStream", in, p.describe)
}

// GetShardIterator creates a service-time cursor under current authorization.
func (p *Streams) GetShardIterator(ctx context.Context, in *api.GetShardIteratorInput) (*api.GetShardIteratorOutput, *awswire.Error) {
	return runStreamCommand(p, ctx, "GetShardIterator", in, p.iterator)
}

// GetRecords reads native records and records the ordinary data API observation.
func (p *Streams) GetRecords(ctx context.Context, in *api.GetRecordsInput) (*api.GetRecordsOutput, *awswire.Error) {
	return runStreamCommand(p, ctx, "GetRecords", in, p.records)
}

func runStreamCommand[I, O any](p *Streams, ctx context.Context, action string, in *I, fn func(context.Context, *I) (*O, error)) (*O, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	out, err := fn(ctx, in)
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	if err := p.record(completion, action, in, out, rejected); err != nil {
		return nil, wireError(err)
	}
	return out, rejected
}
