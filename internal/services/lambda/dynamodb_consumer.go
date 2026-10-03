package lambda

import (
	"context"
	"fmt"
	"time"

	api "stackd/internal/awsapi/dynamodbstreams"
)

type dynamoDBStreamConsumer struct {
	DynamoDBConsumer
	sourceARN string
}

func (c *dynamoDBStreamConsumer) Close() {}
func (c *dynamoDBStreamConsumer) Describe(ctx context.Context) (streamDescription, error) {
	out := streamDescription{Retention: 24 * time.Hour}
	if _, wire := c.Check(ctx); wire != nil {
		return out, wire
	}
	var after *api.ShardId
	for {
		page, wire := c.DynamoDBConsumer.Describe(ctx, &api.DescribeStreamInput{StreamArn: new(api.StreamArn(c.sourceARN)), ExclusiveStartShardId: after})
		if wire != nil {
			return out, wire
		}
		if page == nil || page.StreamDescription == nil {
			return out, fmt.Errorf("stream description missing")
		}
		for _, shard := range page.StreamDescription.Shards {
			out.Shards = append(out.Shards, streamShard{ID: value(shard.ShardId), ParentID: value(shard.ParentShardId)})
		}
		next := page.StreamDescription.LastEvaluatedShardId
		if value(next) == "" {
			return out, nil
		}
		if value(next) == value(after) {
			return out, fmt.Errorf("stream shard pagination did not advance")
		}
		after = next
	}
}
func (c *dynamoDBStreamConsumer) Read(ctx context.Context, mapping EventSourceMappingRecord, shard *StreamShardRecord, iterator string, now time.Time) (streamPage, error) {
	var page streamPage
	if iterator == "" {
		kind := api.ShardIteratorTypeTRIM_HORIZON
		var sequence *api.SequenceNumber
		if shard.Checkpoint != "" {
			kind = api.ShardIteratorTypeAFTER_SEQUENCE_NUMBER
			sequence = new(api.SequenceNumber(shard.Checkpoint))
		}
		out, wire := c.Iterator(ctx, &api.GetShardIteratorInput{StreamArn: new(api.StreamArn(c.sourceARN)), ShardId: new(api.ShardId(shard.Key.ShardID)), ShardIteratorType: &kind, SequenceNumber: sequence})
		if wire != nil {
			return page, wire
		}
		if out == nil {
			return page, fmt.Errorf("stream iterator response missing")
		}
		iterator = value(out.ShardIterator)
	}
	out, wire := c.Records(ctx, &api.GetRecordsInput{ShardIterator: new(api.ShardIterator(iterator)), Limit: new(api.PositiveIntegerObject(1000))})
	if wire != nil {
		return page, wire
	}
	if out == nil {
		return page, fmt.Errorf("stream records response missing")
	}
	page.Iterator, page.Complete = value(out.NextShardIterator), value(out.NextShardIterator) == ""
	for _, native := range out.Records {
		record, err := dynamoDBRecord(mapping, native, now)
		if err != nil {
			return page, err
		}
		page.Records = append(page.Records, record)
		page.Checkpoint = record.Sequence
	}
	return page, nil
}
