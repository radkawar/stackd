package kinesis

import (
	"context"
	"math/big"
	"time"

	api "stackd/internal/awsapi/kinesis"
)

func registerResharding(s *Service) {
	registerControl(s, "SplitShard", s.splitShard)
	registerControl(s, "MergeShards", s.mergeShards)
	registerControl(s, "UpdateShardCount", s.updateShardCount)
	registerOperation(s, "ListShards", s.ListShards)
}

func requireProvisioned(stream StreamRecord) error {
	if err := requireActive(stream); err != nil {
		return err
	}
	if streamMode(stream) != api.StreamModePROVISIONED {
		return failure("ValidationException", "Resharding is not supported for ON_DEMAND streams.")
	}
	return nil
}

func routeByID(shards []ShardRecord, id string) (shardRoute, error) {
	for _, shard := range shards {
		if shard.Key.ID() == id {
			if shard.State != ShardOpen {
				return shardRoute{}, failure("InvalidArgumentException", "The shard has already been merged or split.")
			}
			return parseShardRoute(shard)
		}
	}
	return shardRoute{}, failure("ResourceNotFoundException", "The specified shard does not exist in this stream.")
}

func (s *Service) splitShard(ctx context.Context, tx Transaction, in *api.SplitShardInput) (*api.SplitShardOutput, error) {
	stream, err := s.stream(ctx, tx, value(in.StreamName), value(in.StreamARN), "SplitShard")
	if err != nil {
		return nil, err
	}
	if err := requireProvisioned(stream); err != nil {
		return nil, err
	}
	shards, err := tx.Shards(stream.Key)
	if err != nil {
		return nil, err
	}
	parent, err := routeByID(shards, value(in.ShardToSplit))
	if err != nil {
		return nil, err
	}
	boundary, ok := new(big.Int).SetString(value(in.NewStartingHashKey), 10)
	if !ok || boundary.Cmp(parent.start) <= 0 || boundary.Cmp(parent.end) > 0 {
		return nil, failure("InvalidArgumentException", "NewStartingHashKey must be greater than the shard's starting hash key and no greater than its ending hash key.")
	}
	plan := topologyPlan{stream: stream, peak: int32(*stream.Data.OpenShardCount)}
	plan.split(parent, boundary)
	if err := plan.commit(tx, StreamUpdate{AcceptedAt: s.clock.Now()}); err != nil {
		return nil, err
	}
	return &api.SplitShardOutput{}, nil
}

func (s *Service) mergeShards(ctx context.Context, tx Transaction, in *api.MergeShardsInput) (*api.MergeShardsOutput, error) {
	stream, err := s.stream(ctx, tx, value(in.StreamName), value(in.StreamARN), "MergeShards")
	if err != nil {
		return nil, err
	}
	if err := requireProvisioned(stream); err != nil {
		return nil, err
	}
	shards, err := tx.Shards(stream.Key)
	if err != nil {
		return nil, err
	}
	left, err := routeByID(shards, value(in.ShardToMerge))
	if err != nil {
		return nil, err
	}
	right, err := routeByID(shards, value(in.AdjacentShardToMerge))
	if err != nil {
		return nil, err
	}
	if left.start.Cmp(right.start) > 0 {
		left, right = right, left
	}
	if new(big.Int).Add(left.end, big.NewInt(1)).Cmp(right.start) != 0 {
		return nil, failure("InvalidArgumentException", "The two shards must have adjacent hash key ranges.")
	}
	plan := topologyPlan{stream: stream, peak: int32(*stream.Data.OpenShardCount)}
	plan.merge(left, right)
	if err := plan.commit(tx, StreamUpdate{AcceptedAt: s.clock.Now()}); err != nil {
		return nil, err
	}
	return &api.MergeShardsOutput{}, nil
}

func (s *Service) updateShardCount(ctx context.Context, tx Transaction, in *api.UpdateShardCountInput) (*api.UpdateShardCountOutput, error) {
	stream, err := s.stream(ctx, tx, value(in.StreamName), value(in.StreamARN), "UpdateShardCount")
	if err != nil {
		return nil, err
	}
	if err := requireProvisioned(stream); err != nil {
		return nil, err
	}
	if value(in.ScalingType) != "UNIFORM_SCALING" {
		return nil, failure("ValidationException", "ScalingType must be UNIFORM_SCALING.")
	}
	current, target := int32(*stream.Data.OpenShardCount), int32(*in.TargetShardCount)
	out := &api.UpdateShardCountOutput{StreamName: stream.Data.StreamName, StreamARN: stream.Data.StreamARN, CurrentShardCount: new(api.PositiveIntegerObject(current)), TargetShardCount: new(api.PositiveIntegerObject(target))}
	if target == current {
		return out, nil
	}
	if target < 1 || target < current/2 || int64(target) > int64(current)*2 || target > 10000 || current > 10000 && target >= 10000 {
		return nil, failure("InvalidArgumentException", "TargetShardCount is outside the supported scaling limits.")
	}
	now := s.clock.Now()
	recent := make([]time.Time, 0, len(stream.ShardCountUpdates)+1)
	for _, at := range stream.ShardCountUpdates {
		if at.After(now.Add(-24 * time.Hour)) {
			recent = append(recent, at)
		}
	}
	if len(recent) >= 10 {
		return nil, failure("LimitExceededException", "A stream can be scaled at most ten times in a rolling 24-hour period.")
	}
	stream.ShardCountUpdates = append(recent, now)
	if err := s.scheduleReshard(tx, stream, target, StreamUpdate{AcceptedAt: now}); err != nil {
		return nil, err
	}
	return out, nil
}
