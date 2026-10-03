package kinesis

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/kinesis"
)

func registerControls(s *Service) {
	registerControl(s, "CreateStream", s.createStream)
	registerControl(s, "DeleteStream", s.deleteStream)
	registerControl(s, "DescribeStream", s.describeStream)
	registerControl(s, "DescribeStreamSummary", s.describeStreamSummary)
	registerControl(s, "ListStreams", s.listStreams)
	registerControl(s, "DescribeLimits", s.describeLimits)
	registerControl(s, "IncreaseStreamRetentionPeriod", s.increaseStreamRetentionPeriod)
	registerControl(s, "DecreaseStreamRetentionPeriod", s.decreaseStreamRetentionPeriod)
	registerControl(s, "UpdateStreamMode", s.updateStreamMode)
	registerControl(s, "UpdateMaxRecordSize", s.updateMaxRecordSize)
	registerControl(s, "EnableEnhancedMonitoring", s.enableEnhancedMonitoring)
	registerControl(s, "DisableEnhancedMonitoring", s.disableEnhancedMonitoring)
	registerControl(s, "AddTagsToStream", s.addTagsToStream)
	registerControl(s, "RemoveTagsFromStream", s.removeTagsFromStream)
	registerControl(s, "ListTagsForStream", s.listTagsForStream)
	registerControl(s, "TagResource", s.tagResource)
	registerControl(s, "UntagResource", s.untagResource)
	registerControl(s, "ListTagsForResource", s.listTagsForResource)
	registerControl(s, "PutResourcePolicy", s.putResourcePolicy)
	registerControl(s, "GetResourcePolicy", s.getResourcePolicy)
	registerControl(s, "DeleteResourcePolicy", s.deleteResourcePolicy)
	registerControl(s, "DescribeAccountSettings", s.describeAccountSettings)
	registerControl(s, "UpdateAccountSettings", s.updateAccountSettings)
	registerControl(s, "UpdateStreamWarmThroughput", s.updateStreamWarmThroughput)
}

func (s *Service) createStream(ctx context.Context, tx Transaction, in *api.CreateStreamInput) (*api.CreateStreamOutput, error) {
	key, err := streamKey(ctx, value(in.StreamName), "")
	if err != nil {
		return nil, err
	}
	mode := api.StreamModePROVISIONED
	if in.StreamModeDetails != nil {
		mode = *in.StreamModeDetails.StreamMode
	}
	if err = validMode(mode); err != nil {
		return nil, err
	}
	count := int32(4)
	if mode == api.StreamModePROVISIONED {
		if in.ShardCount == nil {
			return nil, failure("InvalidArgumentException", "ShardCount is required for PROVISIONED mode")
		}
		count = int32(*in.ShardCount)
	} else if in.ShardCount != nil {
		return nil, failure("InvalidArgumentException", "ShardCount must not be specified for ON_DEMAND mode")
	}
	if count < 1 {
		return nil, failure("ValidationException", "ShardCount must be greater than or equal to 1")
	}
	size := int32(1024)
	if in.MaxRecordSizeInKiB != nil {
		size = int32(*in.MaxRecordSizeInKiB)
	}
	if err = validRecordSize(size); err != nil {
		return nil, err
	}
	if len(in.Tags) != 0 {
		if err = validateTags(in.Tags); err != nil {
			return nil, err
		}
	}
	conditions := requestTagConditions(in.Tags)
	if err = s.authorize(ctx, "CreateStream", key.ARN(), conditions); err != nil {
		return nil, err
	}
	if len(in.Tags) != 0 {
		if err = s.authorize(ctx, "AddTagsToStream", key.ARN(), conditions); err != nil {
			return nil, err
		}
	}
	if _, err = tx.Stream(key); err == nil {
		return nil, failure("ResourceInUseException", fmt.Sprintf("Stream %s under account %s already exists.", key.Name, key.AccountID))
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if s.runtime == nil {
		return nil, failure("InternalFailureException", "Kinesis log runtime is not configured", 500)
	}
	if in.WarmThroughputMiBps != nil {
		if err = s.validateWarmThroughput(tx, key.Scope, mode, int32(*in.WarmThroughputMiBps)); err != nil {
			return nil, err
		}
		count = max(count, int32(*in.WarmThroughputMiBps))
	}
	if err = checkStreamCapacity(tx, key.Scope, mode, count, true); err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	record := StreamRecord{Key: key, EngineID: uuid.NewString(), NextPartition: count, Pending: &StreamUpdate{AcceptedAt: now}, Data: api.StreamDescriptionSummary{
		StreamName: new(api.StreamName(key.Name)), StreamARN: new(api.StreamARN(key.ARN())), StreamCreationTimestamp: &now,
		StreamStatus: new(api.StreamStatusCREATING), StreamModeDetails: &api.StreamModeDetails{StreamMode: new(mode)},
		RetentionPeriodHours: new(api.RetentionPeriodHours(24)), OpenShardCount: new(api.ShardCountObject(0)),
		ConsumerCount: new(api.ConsumerCountObject(0)), ChannelCount: new(api.ChannelCountObject(0)), MaxRecordSizeInKiB: new(api.MaxRecordSizeInKiB(size)),
		EncryptionType: new(api.EncryptionTypeNONE), EnhancedMonitoring: api.EnhancedMonitoringList{{ShardLevelMetrics: api.MetricsNameList{}}},
	}}
	if in.WarmThroughputMiBps != nil {
		record.Pending.WarmMiBps = new(int32(*in.WarmThroughputMiBps))
		record.Data.WarmThroughput = &api.WarmThroughputObject{CurrentMiBps: new(api.NaturalIntegerObject(0)), TargetMiBps: new(*in.WarmThroughputMiBps)}
	}
	if err = tx.PutStream(record); err != nil {
		return nil, err
	}
	for _, shard := range initialShards(record, count) {
		if err = tx.PutShard(shard); err != nil {
			return nil, err
		}
	}
	if len(in.Tags) != 0 {
		if err = tx.PutTags(TagRecord{Key: ResourceKey{Scope: key.Scope, ARN: key.ARN()}, Tags: sortedTags(in.Tags)}); err != nil {
			return nil, err
		}
	}
	return &api.CreateStreamOutput{}, nil
}

func checkStreamCapacity(r Reader, scope Scope, mode api.StreamMode, count int32, creating bool) error {
	streams, err := r.Streams(StreamQuery{Scope: scope})
	if err != nil {
		return err
	}
	var onDemand, shards, pendingCreates int32
	for _, stream := range streams {
		pendingMode := api.StreamMode("")
		if stream.Pending != nil {
			pendingMode = stream.Pending.Mode
		}
		if value(stream.Data.StreamStatus) == "CREATING" {
			pendingCreates++
		}
		if streamMode(stream) == api.StreamModeON_DEMAND || pendingMode == api.StreamModeON_DEMAND {
			onDemand++
		}
		if streamMode(stream) == api.StreamModePROVISIONED || pendingMode == api.StreamModePROVISIONED {
			claimed := int32(*stream.Data.OpenShardCount)
			if value(stream.Data.StreamStatus) == "CREATING" {
				claimed = stream.NextPartition
			}
			if stream.Pending != nil {
				claimed = max(claimed, stream.Pending.PeakShardCount)
			}
			shards += claimed
		}
	}
	if creating && pendingCreates >= 5 {
		return failure("LimitExceededException", "At most five streams may be in the CREATING state")
	}
	if mode == api.StreamModeON_DEMAND && onDemand >= 50 {
		return failure("LimitExceededException", "On-demand stream limit exceeded")
	}
	if mode == api.StreamModePROVISIONED && int64(shards)+int64(count) > int64(provisionedShardLimit(scope.Region)) {
		return failure("LimitExceededException", "Shard limit exceeded")
	}
	return nil
}

func provisionedShardLimit(region string) int32 {
	switch region {
	case "us-east-1", "us-west-2", "eu-west-1":
		return 20000
	default:
		return 1000
	}
}

func (s *Service) deleteStream(ctx context.Context, tx Transaction, in *api.DeleteStreamInput) (*api.DeleteStreamOutput, error) {
	stream, err := s.stream(ctx, tx, value(in.StreamName), value(in.StreamARN), "DeleteStream")
	if err != nil {
		return nil, err
	}
	if value(stream.Data.StreamStatus) == "DELETING" {
		return &api.DeleteStreamOutput{}, nil
	}
	if err = requireActive(stream); err != nil {
		return nil, err
	}
	consumers, err := tx.Consumers(stream.Key)
	if err != nil {
		return nil, err
	}
	if len(consumers) != 0 && (in.EnforceConsumerDeletion == nil || !bool(*in.EnforceConsumerDeletion)) {
		return nil, failure("ResourceInUseException", "Stream has registered consumers. Set EnforceConsumerDeletion to delete the stream.")
	}
	stream.Data.StreamStatus = new(api.StreamStatusDELETING)
	stream.Pending = &StreamUpdate{AcceptedAt: s.clock.Now()}
	if err = tx.PutStream(stream); err != nil {
		return nil, err
	}
	return &api.DeleteStreamOutput{}, nil
}

func (s *Service) describeStreamSummary(ctx context.Context, tx Transaction, in *api.DescribeStreamSummaryInput) (*api.DescribeStreamSummaryOutput, error) {
	stream, err := s.stream(ctx, tx, value(in.StreamName), value(in.StreamARN), "DescribeStreamSummary")
	if err != nil {
		return nil, err
	}
	if *stream.Data.StreamModeDetails.StreamMode == api.StreamModeON_DEMAND {
		stream.Data.RecordDistributionStrategy = new(api.String("USER_PARTITION_KEY"))
	}
	return &api.DescribeStreamSummaryOutput{StreamDescriptionSummary: &stream.Data}, nil
}

func (s *Service) describeStream(ctx context.Context, tx Transaction, in *api.DescribeStreamInput) (*api.DescribeStreamOutput, error) {
	stream, err := s.stream(ctx, tx, value(in.StreamName), value(in.StreamARN), "DescribeStream")
	if err != nil {
		return nil, err
	}
	limit := 100
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	if limit < 1 || limit > 10000 {
		return nil, failure("ValidationException", "Limit must be between 1 and 10000")
	}
	description, err := describeStreamPage(tx, stream, value(in.ExclusiveStartShardId), limit)
	if err != nil {
		return nil, err
	}
	return &api.DescribeStreamOutput{StreamDescription: description}, nil
}

func describeStreamPage(r Reader, stream StreamRecord, after string, limit int) (*api.StreamDescription, error) {
	shards, err := r.Shards(stream.Key)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(shards, func(a, b ShardRecord) int { return strings.Compare(a.Key.ID(), b.Key.ID()) })
	out := &api.StreamDescription{StreamARN: stream.Data.StreamARN, StreamName: stream.Data.StreamName, StreamCreationTimestamp: stream.Data.StreamCreationTimestamp,
		StreamStatus: stream.Data.StreamStatus, StreamModeDetails: stream.Data.StreamModeDetails, RetentionPeriodHours: stream.Data.RetentionPeriodHours,
		EncryptionType: stream.Data.EncryptionType, KeyId: stream.Data.KeyId, EnhancedMonitoring: stream.Data.EnhancedMonitoring,
		Shards: api.ShardList{}, HasMoreShards: new(api.BooleanObject(false))}
	for _, shard := range shards {
		if shard.State == ShardOpening || shard.Key.ID() <= after {
			continue
		}
		if len(out.Shards) == limit {
			out.HasMoreShards = new(api.BooleanObject(true))
			break
		}
		out.Shards = append(out.Shards, shard.Data)
	}
	return out, nil
}

func (s *Service) listStreams(ctx context.Context, tx Transaction, in *api.ListStreamsInput) (*api.ListStreamsOutput, error) {
	if err := s.authorize(ctx, "ListStreams", "*", nil); err != nil {
		return nil, err
	}
	if in.NextToken != nil && in.ExclusiveStartStreamName != nil {
		return nil, failure("InvalidArgumentException", "ExclusiveStartStreamName and NextToken cannot be provided together.")
	}
	limit := 100
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	if limit < 1 || limit > 10000 {
		return nil, failure("ValidationException", "Limit must be between 1 and 10000")
	}
	scope := scopeFor(ctx)
	collection := (StreamKey{Scope: scope}).ARN() + "/ListStreams"
	after, err := decodeCursor(in.NextToken, collection, s.clock.Now())
	if err != nil {
		return nil, err
	}
	if in.NextToken == nil {
		after = value(in.ExclusiveStartStreamName)
	}
	if after != "" && !streamNamePattern.MatchString(after) {
		return nil, failure("InvalidArgumentException", "Invalid NextToken.")
	}
	streams, err := tx.Streams(StreamQuery{Scope: scope, After: after, Limit: limit})
	if err != nil {
		return nil, err
	}
	// A full native page carries a continuation even when its next page is empty.
	more := len(streams) == limit
	out := &api.ListStreamsOutput{HasMoreStreams: new(api.BooleanObject(more)), StreamNames: api.StreamNameList{}, StreamSummaries: api.StreamSummaryList{}}
	for _, stream := range streams {
		out.StreamNames = append(out.StreamNames, api.StreamName(stream.Key.Name))
		out.StreamSummaries = append(out.StreamSummaries, api.StreamSummary{StreamARN: stream.Data.StreamARN, StreamName: stream.Data.StreamName, StreamCreationTimestamp: stream.Data.StreamCreationTimestamp, StreamModeDetails: stream.Data.StreamModeDetails, StreamStatus: stream.Data.StreamStatus})
	}
	if more {
		out.NextToken = encodeCursor(collection, streams[len(streams)-1].Key.Name, s.clock.Now())
	}
	return out, nil
}

func (s *Service) describeLimits(ctx context.Context, tx Transaction, in *api.DescribeLimitsInput) (*api.DescribeLimitsOutput, error) {
	if err := s.authorize(ctx, "DescribeLimits", "*", nil); err != nil {
		return nil, err
	}
	streams, err := tx.Streams(StreamQuery{Scope: scopeFor(ctx)})
	if err != nil {
		return nil, err
	}
	var onDemand api.OnDemandStreamCountObject
	var shards api.ShardCountObject
	for _, stream := range streams {
		if streamMode(stream) == api.StreamModeON_DEMAND {
			onDemand++
		} else if stream.Data.OpenShardCount != nil {
			shards += *stream.Data.OpenShardCount
		}
	}
	return &api.DescribeLimitsOutput{OnDemandStreamCount: &onDemand, OnDemandStreamCountLimit: new(api.OnDemandStreamCountLimitObject(50)), OpenShardCount: &shards, ShardLimit: new(api.ShardCountObject(provisionedShardLimit(scopeFor(ctx).Region))), ChannelCount: new(api.ChannelCountObject(0)), ChannelCountLimit: new(api.ChannelCountObject(100))}, nil
}
