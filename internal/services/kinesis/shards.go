package kinesis

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/kinesis"
)

type shardListCursor struct {
	StreamARN string
	EngineID  string
	After     string
	Filter    api.ShardFilter
}

func (s *Service) listShards(ctx context.Context, tx Transaction, in *api.ListShardsInput) (*api.ListShardsOutput, error) {
	now := s.clock.Now()
	collection := (StreamKey{Scope: scopeFor(ctx)}).ARN() + "/ListShards"
	cursor := shardListCursor{Filter: api.ShardFilter{Type: new(api.ShardFilterTypeFROM_TRIM_HORIZON)}}
	name, arn := value(in.StreamName), value(in.StreamARN)
	if in.NextToken != nil {
		if in.StreamCreationTimestamp != nil || in.ExclusiveStartShardId != nil || in.ShardFilter != nil {
			return nil, failure("InvalidArgumentException", "NextToken cannot be combined with a creation timestamp, starting shard or shard filter.")
		}
		position, err := decodeCursor(in.NextToken, collection, now)
		if err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(position), &cursor) != nil || cursor.StreamARN == "" || cursor.EngineID == "" || cursor.After == "" {
			return nil, failure("InvalidArgumentException", "Invalid NextToken.")
		}
		if arn != "" && arn != cursor.StreamARN {
			return nil, failure("InvalidArgumentException", "StreamARN does not match NextToken.")
		}
		arn = cursor.StreamARN
	} else {
		if in.ShardFilter != nil {
			if in.ExclusiveStartShardId != nil {
				return nil, failure("InvalidArgumentException", "ShardFilter and ExclusiveStartShardId cannot be combined.")
			}
			cursor.Filter = *in.ShardFilter
		}
		cursor.After = value(in.ExclusiveStartShardId)
		if cursor.Filter.ShardId != nil {
			cursor.After = value(cursor.Filter.ShardId)
		}
	}
	if err := validateShardFilter(cursor.Filter); err != nil {
		return nil, err
	}
	stream, err := s.stream(ctx, tx, name, arn, "ListShards")
	if err != nil {
		return nil, err
	}
	if err := requireReadable(stream); err != nil {
		return nil, err
	}
	if in.NextToken != nil && cursor.EngineID != stream.EngineID {
		return nil, failure("InvalidArgumentException", "NextToken refers to a different stream incarnation.")
	}
	if in.StreamCreationTimestamp != nil && in.StreamCreationTimestamp.UnixMilli() != stream.Data.StreamCreationTimestamp.UnixMilli() {
		return nil, failure("ResourceNotFoundException", "No stream exists with the specified creation timestamp.")
	}
	limit := 1000
	if in.MaxResults != nil {
		if *in.MaxResults < 1 || *in.MaxResults > 10000 {
			return nil, failure("ValidationException", "MaxResults must be between 1 and 10000.")
		}
		limit = min(int(*in.MaxResults), 1000)
	}
	shards, err := tx.Shards(stream.Key)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(shards, func(a, b ShardRecord) int { return strings.Compare(a.Key.ID(), b.Key.ID()) })
	cutoff := now.Add(-time.Duration(*stream.Data.RetentionPeriodHours) * time.Hour)
	if cutoff.Before(*stream.Data.StreamCreationTimestamp) {
		cutoff = *stream.Data.StreamCreationTimestamp
	}
	if *cursor.Filter.Type == api.ShardFilterTypeAT_TIMESTAMP || *cursor.Filter.Type == api.ShardFilterTypeFROM_TIMESTAMP {
		if cursor.Filter.Timestamp.Before(cutoff) {
			return nil, failure("InvalidArgumentException", "ShardFilter Timestamp cannot be older than TRIM_HORIZON of the stream.")
		}
		if cursor.Filter.Timestamp.After(now) {
			return nil, failure("InvalidArgumentException", "ShardFilter Timestamp must not be greater than current time.")
		}
	}
	out := &api.ListShardsOutput{Shards: api.ShardList{}}
	for _, shard := range shards {
		if shard.Key.ID() <= cursor.After || !matchesShardFilter(shard, cursor.Filter, cutoff) {
			continue
		}
		if len(out.Shards) == limit {
			cursor.StreamARN, cursor.EngineID = stream.Key.ARN(), stream.EngineID
			cursor.After = value(out.Shards[len(out.Shards)-1].ShardId)
			position, err := json.Marshal(cursor)
			if err != nil {
				return nil, err
			}
			out.NextToken = encodeCursor(collection, string(position), now)
			break
		}
		out.Shards = append(out.Shards, shard.Data)
	}
	return out, nil
}

func validateShardFilter(filter api.ShardFilter) error {
	if filter.Type == nil {
		return failure("ValidationException", "ShardFilter.Type is required.")
	}
	switch *filter.Type {
	case api.ShardFilterTypeAFTER_SHARD_ID:
		if filter.ShardId == nil || value(filter.ShardId) == "" {
			return failure("InvalidArgumentException", "AFTER_SHARD_ID requires ShardId.")
		}
	case api.ShardFilterTypeAT_TIMESTAMP, api.ShardFilterTypeFROM_TIMESTAMP:
		if filter.Timestamp == nil {
			return failure("InvalidArgumentException", "The timestamp shard filter requires Timestamp.")
		}
	case api.ShardFilterTypeAT_LATEST, api.ShardFilterTypeAT_TRIM_HORIZON, api.ShardFilterTypeFROM_TRIM_HORIZON:
	default:
		return failure("ValidationException", "Invalid ShardFilter.Type.")
	}
	return nil
}

func matchesShardFilter(shard ShardRecord, filter api.ShardFilter, cutoff time.Time) bool {
	if shard.State == ShardOpening || shard.State == ShardClosed && shard.ClosedAt.Before(cutoff) {
		return false
	}
	switch *filter.Type {
	case api.ShardFilterTypeAT_LATEST:
		return shard.State == ShardOpen
	case api.ShardFilterTypeAT_TRIM_HORIZON:
		return !shard.OpenedAt.After(cutoff) && (shard.State == ShardOpen || !shard.ClosedAt.Before(cutoff))
	case api.ShardFilterTypeAT_TIMESTAMP:
		return !shard.OpenedAt.After(*filter.Timestamp) && (shard.State == ShardOpen || !shard.ClosedAt.Before(*filter.Timestamp))
	case api.ShardFilterTypeFROM_TIMESTAMP:
		return shard.State == ShardOpen || !shard.ClosedAt.Before(*filter.Timestamp)
	default:
		return true
	}
}
