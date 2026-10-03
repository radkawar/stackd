package kinesis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	api "stackd/internal/awsapi/kinesis"
)

type shardCursor struct {
	Scope     Scope     `json:"scope"`
	Stream    StreamKey `json:"stream"`
	EngineID  string    `json:"engine"`
	ShardID   string    `json:"shard"`
	Offset    int64     `json:"offset"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func encodeShardCursor(scope Scope, stream StreamRecord, shard ShardRecord, offset int64, now time.Time) *api.ShardIterator {
	data, _ := json.Marshal(shardCursor{Scope: scope, Stream: stream.Key, EngineID: stream.EngineID, ShardID: shard.Key.ID(), Offset: offset, ExpiresAt: now.Add(5 * time.Minute)})
	return new(api.ShardIterator(base64.RawURLEncoding.EncodeToString(data)))
}

func decodeShardCursor(token string, scope Scope, now time.Time) (shardCursor, error) {
	var cursor shardCursor
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Scope != scope || cursor.Stream.Partition != scope.Partition || cursor.Stream.Region != scope.Region || !accountPattern.MatchString(cursor.Stream.AccountID) || !streamNamePattern.MatchString(cursor.Stream.Name) || cursor.EngineID == "" || cursor.ShardID == "" || cursor.Offset < 0 || cursor.ExpiresAt.IsZero() {
		return cursor, failure("InvalidArgumentException", "Invalid ShardIterator.")
	}
	if !now.Before(cursor.ExpiresAt) {
		return cursor, failure("ExpiredIteratorException", "The iterator has expired. Please obtain a new shard iterator.")
	}
	return cursor, nil
}

func (s *Service) getShardIterator(ctx context.Context, in *api.GetShardIteratorInput) (*api.GetShardIteratorOutput, error) {
	if in == nil || in.ShardId == nil || value(in.ShardId) == "" || in.ShardIteratorType == nil {
		return nil, failure("ValidationException", "ShardId and ShardIteratorType are required.")
	}
	switch *in.ShardIteratorType {
	case api.ShardIteratorTypeAT_SEQUENCE_NUMBER, api.ShardIteratorTypeAFTER_SEQUENCE_NUMBER, api.ShardIteratorTypeTRIM_HORIZON, api.ShardIteratorTypeLATEST, api.ShardIteratorTypeAT_TIMESTAMP:
	default:
		return nil, failure("ValidationException", "Invalid ShardIteratorType.")
	}
	if in.StartingSequenceNumber != nil && !decimalCoordinate.MatchString(value(in.StartingSequenceNumber)) {
		return nil, failure("ValidationException", "StartingSequenceNumber must be a decimal sequence number.")
	}
	if isDryRun(in.DryRun) {
		if _, err := s.dryRunStream(ctx, value(in.StreamName), value(in.StreamARN), "GetShardIterator"); err != nil {
			return nil, err
		}
		return nil, dryRunResult("GetShardIterator")
	}
	stream, shards, log, release, err := s.openStream(ctx, value(in.StreamName), value(in.StreamARN), "GetShardIterator")
	if err != nil {
		return nil, err
	}
	defer release()
	shard, err := findShard(shards, value(in.ShardId))
	if err != nil {
		return nil, err
	}
	if err := s.admitRead(ctx, shard, "GetShardIterator"); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	offset, err := startOffset(ctx, log, stream, shard, *in.ShardIteratorType, value(in.StartingSequenceNumber), (*time.Time)(in.Timestamp), now)
	if err != nil {
		return nil, err
	}
	return &api.GetShardIteratorOutput{ShardIterator: encodeShardCursor(scopeFor(ctx), stream, shard, offset, now)}, nil
}

func (s *Service) getRecords(ctx context.Context, in *api.GetRecordsInput) (*api.GetRecordsOutput, error) {
	if in == nil || in.ShardIterator == nil || value(in.ShardIterator) == "" {
		return nil, failure("ValidationException", "ShardIterator is required.")
	}
	limit := 10000
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	if limit < 1 || limit > 10000 {
		return nil, failure("ValidationException", "Limit must be between 1 and 10000.")
	}
	cursor, err := decodeShardCursor(value(in.ShardIterator), scopeFor(ctx), s.clock.Now())
	if err != nil {
		return nil, err
	}
	target := cursor.Stream
	if in.StreamARN != nil {
		target, err = streamKey(ctx, "", value(in.StreamARN))
		if err != nil {
			return nil, err
		}
	}
	// Native authorization uses an explicitly supplied ARN before checking its
	// agreement with the iterator. It does not require the stream to exist.
	var stream StreamRecord
	err = s.repository.View(ctx, func(r Reader) error {
		if err := s.authorizeResource(r.Context(), r, ResourceKey{Scope: target.Scope, ARN: target.ARN()}, nil, "GetRecords"); err != nil {
			return err
		}
		if target != cursor.Stream || isDryRun(in.DryRun) {
			return nil
		}
		stream, err = r.Stream(target)
		return err
	})
	if err != nil {
		return nil, err
	}
	if target != cursor.Stream {
		return nil, failure("InvalidArgumentException", "Input stream name "+cursor.Stream.Name+" doesn't match the inferred name in stream arn "+target.Name)
	}
	if isDryRun(in.DryRun) {
		return nil, dryRunResult("GetRecords")
	}
	stream, shards, log, release, err := s.openStreamRecord(ctx, stream, target.ARN(), "GetRecords")
	if err != nil {
		return nil, err
	}
	defer release()
	if stream.EngineID != cursor.EngineID {
		return nil, failure("ResourceNotFoundException", "The shard iterator refers to a deleted stream incarnation.")
	}
	shard, err := findShard(shards, cursor.ShardID)
	if err != nil {
		return nil, err
	}
	if err := s.admitRead(ctx, shard, "GetRecords"); err != nil {
		return nil, err
	}
	page, err := s.readShard(ctx, stream, shard, shards, log, cursor.Offset, limit, maxDataBytes, true)
	if err != nil {
		return nil, err
	}
	s.observeReadBytes(shard, page.Bytes)
	s.dataSample(ctx, "GetRecords.Bytes", shard.Key.ID(), float64(page.Bytes))
	s.dataSample(ctx, "GetRecords.Records", shard.Key.ID(), float64(len(page.Records)))
	s.dataSample(ctx, "GetRecords.IteratorAgeMilliseconds", shard.Key.ID(), float64(page.MillisBehindLatest))
	s.dataSample(ctx, "GetRecords.Success", shard.Key.ID(), 1)
	out := &api.GetRecordsOutput{Records: page.Records, ChildShards: page.ChildShards, MillisBehindLatest: new(api.MillisBehindLatest(page.MillisBehindLatest))}
	if !page.Closed {
		out.NextShardIterator = encodeShardCursor(scopeFor(ctx), stream, shard, page.NextOffset, s.clock.Now())
	}
	return out, nil
}
