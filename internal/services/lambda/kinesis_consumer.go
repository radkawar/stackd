package lambda

import (
	"context"
	"fmt"
	"strings"
	"time"

	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
)

type kinesisSubscription struct {
	events <-chan api.SubscribeToShardEventStream
	cancel context.CancelFunc
}
type kinesisStreamConsumer struct {
	consumer                      KinesisConsumer
	sourceARN, streamARN, roleARN string
	shards                        map[string]api.Shard
	subscriptions                 map[string]kinesisSubscription
}

func (c *kinesisStreamConsumer) Close() {
	for id, sub := range c.subscriptions {
		sub.cancel()
		delete(c.subscriptions, id)
	}
}
func (c *kinesisStreamConsumer) LatestSequence(ctx context.Context, shard string) (string, *awswire.Error) {
	return c.consumer.LatestSequence(ctx, shard)
}
func (c *kinesisStreamConsumer) Describe(ctx context.Context) (streamDescription, error) {
	var out streamDescription
	checked, wire := c.consumer.Check(ctx)
	if wire != nil {
		c.Close()
		return out, wire
	}
	if checked == nil || checked.RetentionPeriodHours == nil {
		return out, fmt.Errorf("kinesis stream description missing retention")
	}
	c.streamARN = value(checked.StreamARN)
	out.Retention = time.Duration(*checked.RetentionPeriodHours) * time.Hour
	c.shards = make(map[string]api.Shard)
	if strings.Contains(c.sourceARN, "/consumer/") {
		for _, shard := range checked.Shards {
			id := value(shard.ShardId)
			out.Shards = append(out.Shards, streamShard{ID: id, ParentID: value(shard.ParentShardId), AdjacentParentID: value(shard.AdjacentParentShardId)})
			c.shards[id] = shard
		}
		return out, nil
	}
	var after *api.ShardId
	for {
		page, wire := c.consumer.Describe(ctx, &api.DescribeStreamInput{StreamARN: new(api.StreamARN(c.streamARN)), ExclusiveStartShardId: after})
		if wire != nil {
			return out, wire
		}
		if page == nil || page.StreamDescription == nil {
			return out, fmt.Errorf("kinesis stream description missing")
		}
		d := page.StreamDescription
		for _, shard := range d.Shards {
			id := value(shard.ShardId)
			out.Shards = append(out.Shards, streamShard{ID: id, ParentID: value(shard.ParentShardId), AdjacentParentID: value(shard.AdjacentParentShardId)})
			c.shards[id] = shard
		}
		if d.HasMoreShards == nil || !bool(*d.HasMoreShards) {
			return out, nil
		}
		if len(d.Shards) == 0 || value(d.Shards[len(d.Shards)-1].ShardId) == value(after) {
			return out, fmt.Errorf("kinesis shard pagination did not advance")
		}
		after = d.Shards[len(d.Shards)-1].ShardId
	}
}
func kinesisStartingPosition(shard *StreamShardRecord) *api.StartingPosition {
	position := &api.StartingPosition{Type: new(api.ShardIteratorTypeTRIM_HORIZON)}
	if shard.Checkpoint != "" {
		position.Type = new(api.ShardIteratorTypeAFTER_SEQUENCE_NUMBER)
		position.SequenceNumber = new(api.SequenceNumber(shard.Checkpoint))
	} else if !shard.StartingPositionTimestamp.IsZero() {
		position.Type = new(api.ShardIteratorTypeAT_TIMESTAMP)
		position.Timestamp = new(api.Timestamp(shard.StartingPositionTimestamp))
	}
	return position
}
func (c *kinesisStreamConsumer) Read(ctx context.Context, mapping EventSourceMappingRecord, shard *StreamShardRecord, iterator string, now time.Time) (streamPage, error) {
	var page streamPage
	var records api.RecordList
	fanout := strings.Contains(c.sourceARN, "/consumer/")
	if fanout {
		sub, exists := c.subscriptions[shard.Key.ShardID]
		if !exists {
			subctx, cancel := context.WithCancel(ctx)
			out, wire := c.consumer.Subscribe(subctx, &api.SubscribeToShardInput{ConsumerARN: new(api.ConsumerARN(c.sourceARN)), ShardId: new(api.ShardId(shard.Key.ShardID)), StartingPosition: kinesisStartingPosition(shard)})
			if wire != nil {
				cancel()
				return page, wire
			}
			if out == nil || out.EventStream == nil {
				cancel()
				return page, fmt.Errorf("kinesis subscription response missing")
			}
			sub = kinesisSubscription{events: out.EventStream, cancel: cancel}
			c.subscriptions[shard.Key.ShardID] = sub
		}
		select {
		case <-ctx.Done():
			return page, ctx.Err()
		case frame, open := <-sub.events:
			if !open {
				sub.cancel()
				delete(c.subscriptions, shard.Key.ShardID)
				return page, nil
			}
			if frame.SubscribeToShardEvent == nil {
				sub.cancel()
				delete(c.subscriptions, shard.Key.ShardID)
				return page, kinesisSubscriptionError(frame)
			}
			event := frame.SubscribeToShardEvent
			records = event.Records
			page.Checkpoint = value(event.ContinuationSequenceNumber)
			page.Complete = page.Checkpoint == ""
			if page.Complete {
				sub.cancel()
				delete(c.subscriptions, shard.Key.ShardID)
			}
		default:
			return page, nil
		}
	} else {
		if iterator == "" {
			position := kinesisStartingPosition(shard)
			out, wire := c.consumer.Iterator(ctx, &api.GetShardIteratorInput{StreamARN: new(api.StreamARN(c.streamARN)), ShardId: new(api.ShardId(shard.Key.ShardID)), ShardIteratorType: position.Type, StartingSequenceNumber: position.SequenceNumber, Timestamp: position.Timestamp})
			if wire != nil {
				return page, wire
			}
			if out == nil {
				return page, fmt.Errorf("kinesis iterator response missing")
			}
			iterator = value(out.ShardIterator)
		}
		out, wire := c.consumer.Records(ctx, &api.GetRecordsInput{StreamARN: new(api.StreamARN(c.streamARN)), ShardIterator: new(api.ShardIterator(iterator)), Limit: new(api.GetRecordsInputLimit(1000))})
		if wire != nil {
			return page, wire
		}
		if out == nil {
			return page, fmt.Errorf("kinesis records response missing")
		}
		records = out.Records
		page.Iterator = value(out.NextShardIterator)
		page.Complete = page.Iterator == ""
		if len(records) > 0 {
			page.Checkpoint = value(records[len(records)-1].SequenceNumber)
		}
	}
	for _, native := range records {
		projected, err := kinesisRecords(mapping, c.roleARN, c.sourceARN, shard.Key.ShardID, native, c.shards[shard.Key.ShardID], fanout, now)
		if err != nil {
			return page, err
		}
		page.Records = append(page.Records, projected...)
	}
	return page, nil
}
func kinesisSubscriptionError(frame api.SubscribeToShardEventStream) error {
	code, message := "InternalFailure", "Kinesis subscription ended without a data frame"
	switch {
	case frame.InternalFailureException != nil:
		code, message = "InternalFailureException", value(frame.InternalFailureException.Message)
	case frame.KMSAccessDeniedException != nil:
		code, message = "KMSAccessDeniedException", value(frame.KMSAccessDeniedException.Message)
	case frame.KMSDisabledException != nil:
		code, message = "KMSDisabledException", value(frame.KMSDisabledException.Message)
	case frame.KMSInvalidStateException != nil:
		code, message = "KMSInvalidStateException", value(frame.KMSInvalidStateException.Message)
	case frame.KMSNotFoundException != nil:
		code, message = "KMSNotFoundException", value(frame.KMSNotFoundException.Message)
	case frame.KMSOptInRequired != nil:
		code, message = "KMSOptInRequired", value(frame.KMSOptInRequired.Message)
	case frame.KMSThrottlingException != nil:
		code, message = "KMSThrottlingException", value(frame.KMSThrottlingException.Message)
	case frame.ResourceInUseException != nil:
		code, message = "ResourceInUseException", value(frame.ResourceInUseException.Message)
	case frame.ResourceNotFoundException != nil:
		code, message = "ResourceNotFoundException", value(frame.ResourceNotFoundException.Message)
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: 400, Type: "User"}
}
