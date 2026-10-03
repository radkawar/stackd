package kinesis

import (
	"context"
	"math"
	"strings"

	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
)

// CheckConsumeStream evaluates the source permissions required by Lambda without
// issuing synthetic API calls. Shared readers require DescribeStream, GetRecords
// and GetShardIterator. Enhanced readers instead require DescribeStreamSummary,
// ListShards, both shared read permissions, and SubscribeToShard on the consumer.
// The complete retained description also lets enhanced readers discover shards
// without inventing a DescribeStream permission their native contract lacks.
func (s *Service) CheckConsumeStream(ctx context.Context, sourceARN string) (*api.StreamDescription, *awswire.Error) {
	var out *api.StreamDescription
	err := s.repository.View(ctx, func(r Reader) error {
		ctx := r.Context()
		var stream StreamRecord
		var err error
		if strings.Contains(sourceARN, "/consumer/") {
			stream, err = s.consumingStream(ctx, r, sourceARN, "SubscribeToShard")
			if err == nil {
				err = s.authorizeResource(ctx, r, ResourceKey{Scope: stream.Key.Scope, ARN: stream.Key.ARN()}, nil, "DescribeStreamSummary", "GetRecords", "GetShardIterator", "ListShards")
			}
		} else {
			stream, err = s.stream(ctx, r, "", sourceARN, "DescribeStream", "GetRecords", "GetShardIterator")
		}
		if err != nil {
			return err
		}
		if err := requireReadable(stream); err != nil {
			return err
		}
		out, err = describeStreamPage(r, stream, "", math.MaxInt)
		return err
	})
	return out, wireError(err)
}

// LatestSequence returns an opaque position after the shard's current records.
// Both AT and AFTER sequence iterators resume at that position, including an
// empty shard. Unlike a wire iterator, it survives reopen and record trimming.
// An enhanced consumer authorizes its own subscription, not shared-throughput
// reads on its parent stream. This state read does not synthesize an API event.
func (s *Service) LatestSequence(ctx context.Context, sourceARN, shardID string) (string, *awswire.Error) {
	var stream StreamRecord
	action := "GetShardIterator"
	if strings.Contains(sourceARN, "/consumer/") {
		action = "SubscribeToShard"
	}
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		stream, err = s.consumingStream(r.Context(), r, sourceARN, action)
		return err
	})
	if err != nil {
		return "", wireError(err)
	}
	_, shards, log, release, err := s.openStreamRecord(ctx, stream, sourceARN, action)
	if err != nil {
		return "", wireError(err)
	}
	defer release()
	shard, err := findShard(shards, shardID)
	if err != nil {
		return "", wireError(err)
	}
	bounds, err := log.Bounds(ctx, shard.Key.Partition)
	if err != nil {
		return "", wireError(err)
	}
	return string(sequenceFor(shard).checkpoint(bounds.End)), nil
}

// consumingStream binds authorization to the selected source. Consumer policies
// do not implicitly grant any shared-throughput operation on the parent stream.
func (s *Service) consumingStream(ctx context.Context, r Reader, sourceARN, action string) (StreamRecord, error) {
	if !strings.Contains(sourceARN, "/consumer/") {
		return s.stream(ctx, r, "", sourceARN, action)
	}
	consumer, err := s.consumer(ctx, r, "", sourceARN, "", action)
	if err != nil {
		return StreamRecord{}, err
	}
	if value(consumer.Data.ConsumerStatus) != "ACTIVE" {
		return StreamRecord{}, failure("ResourceInUseException", "Consumer "+sourceARN+" is not ACTIVE.")
	}
	return r.Stream(consumer.Key.Stream)
}
