package dynamodb

import (
	"context"

	api "stackd/internal/awsapi/dynamodbstreams"
	"stackd/internal/awswire"
)

// CheckConsumeStream checks the reads used by a known-stream consumer.
// ListStreams is not required for native Lambda admission, even when denied.
// The returned description uses the same retained generation as DescribeStream.
func (p *Streams) CheckConsumeStream(ctx context.Context, resource string) (*api.StreamDescription, *awswire.Error) {
	g, err := p.resolve(ctx, resource, "GetRecords", "GetShardIterator", "DescribeStream")
	if err != nil {
		return nil, wireError(err)
	}
	out, err := p.describeGeneration(ctx, g, &api.DescribeStreamInput{}, 100)
	if err != nil {
		return nil, wireError(err)
	}
	return out.StreamDescription, nil
}

// LatestSequence exposes the retained shard high-water to an authorized source
// consumer. Unlike a short-lived wire iterator, this position survives restart
// and record trimming. The consumer issues its normal iterator after retaining
// the position; this state read does not synthesize an API observation.
func (p *Streams) LatestSequence(ctx context.Context, resource, shardID string) (string, *awswire.Error) {
	g, err := p.resolve(ctx, resource, "GetShardIterator")
	if err != nil {
		return "", wireError(err)
	}
	if err := p.refresh(ctx, g); err != nil {
		return "", wireError(err)
	}
	var sequence string
	err = p.s.repository.View(ctx, func(r Reader) error {
		if streamExpired(g, p.s.clock.Now()) {
			return ErrNotFound
		}
		shard, err := getStreamShard(r, g.Key.ResourceARN, shardID)
		if err != nil {
			return err
		}
		sequence = shard.Checkpoint
		return nil
	})
	return sequence, wireError(err)
}
