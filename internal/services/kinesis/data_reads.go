package kinesis

import (
	"context"
	"time"

	engine "stackd/engine/kinesis"
	api "stackd/internal/awsapi/kinesis"
)

type recordPage struct {
	Records            api.RecordList
	NextOffset         int64
	Closed             bool
	ChildShards        api.ChildShardList
	MillisBehindLatest int64
	Bytes              int
}

func retentionCutoff(stream StreamRecord, now time.Time) time.Time {
	hours := 24
	if stream.Data.RetentionPeriodHours != nil {
		hours = int(*stream.Data.RetentionPeriodHours)
	}
	return now.Add(-time.Duration(hours) * time.Hour)
}

func startOffset(ctx context.Context, log engine.Log, stream StreamRecord, shard ShardRecord, kind api.ShardIteratorType, sequence string, at *time.Time, now time.Time) (int64, error) {
	sequenceMode := kind == api.ShardIteratorTypeAT_SEQUENCE_NUMBER || kind == api.ShardIteratorTypeAFTER_SEQUENCE_NUMBER
	if sequenceMode && sequence == "" {
		return 0, failure("InvalidArgumentException", "StartingSequenceNumber is required for the requested iterator type.")
	}
	if !sequenceMode && sequence != "" {
		return 0, failure("InvalidArgumentException", "StartingSequenceNumber is only valid for a sequence iterator type.")
	}
	if kind == api.ShardIteratorTypeAT_TIMESTAMP {
		if at == nil {
			return 0, failure("InvalidArgumentException", "Timestamp is required for AT_TIMESTAMP.")
		}
		if at.After(now) {
			return 0, failure("InvalidArgumentException", "Timestamp must not be in the future.")
		}
	} else if at != nil {
		return 0, failure("InvalidArgumentException", "Timestamp is only valid for AT_TIMESTAMP.")
	}
	bounds, err := log.Bounds(ctx, shard.Key.Partition)
	if err != nil {
		return 0, err
	}
	cutoff := retentionCutoff(stream, now)
	retained, err := log.OffsetAt(ctx, shard.Key.Partition, cutoff)
	if err != nil {
		return 0, err
	}
	start := max(bounds.Start, retained)
	switch kind {
	case api.ShardIteratorTypeTRIM_HORIZON:
		return start, nil
	case api.ShardIteratorTypeLATEST:
		return bounds.End, nil
	case api.ShardIteratorTypeAT_TIMESTAMP:
		if !at.After(cutoff) {
			return start, nil
		}
		offset, err := log.OffsetAt(ctx, shard.Key.Partition, *at)
		return max(start, offset), err
	case api.ShardIteratorTypeAT_SEQUENCE_NUMBER, api.ShardIteratorTypeAFTER_SEQUENCE_NUMBER:
		offset, terminal, checkpoint, err := sequenceFor(shard).position(sequence)
		if err != nil {
			return 0, err
		}
		if terminal {
			if shard.State != ShardClosed {
				return 0, failure("InvalidArgumentException", "The sequence number is not a record in the requested shard.")
			}
			return bounds.End, nil
		}
		if offset > bounds.End || offset == bounds.End && !checkpoint {
			return 0, failure("InvalidArgumentException", "The sequence number is beyond the end of the requested shard.")
		}
		if kind == api.ShardIteratorTypeAFTER_SEQUENCE_NUMBER && !checkpoint {
			offset++
		}
		return max(start, offset), nil
	default:
		return 0, failure("InvalidArgumentException", "Invalid shard iterator type.")
	}
}

// readShard owns visibility and conversion, not admission or resource locking.
// An empty native fetch below its end is a heartbeat, never evidence of EOF.
func (s *Service) readShard(ctx context.Context, stream StreamRecord, shard ShardRecord, shards []ShardRecord, log engine.Log, offset int64, limit, maxBytes int, includePartitionKeys bool) (recordPage, error) {
	page := recordPage{Records: api.RecordList{}, NextOffset: offset}
	now := s.clock.Now()
	bounds, err := log.Bounds(ctx, shard.Key.Partition)
	if err != nil {
		return page, err
	}
	if offset < 0 || offset > bounds.End {
		return page, failure("InvalidArgumentException", "Invalid record position.")
	}
	cutoff := retentionCutoff(stream, now)
	retained, err := log.OffsetAt(ctx, shard.Key.Partition, cutoff)
	if err != nil {
		return page, err
	}
	page.NextOffset = max(offset, bounds.Start, retained)
	var lastArrival time.Time
	sequence := sequenceFor(shard)
	if page.NextOffset < bounds.End {
		result, err := log.Read(ctx, shard.Key.Partition, page.NextOffset, limit, maxDataBytes)
		if err != nil {
			return page, err
		}
		bounds = result.Bounds
		// Select the plaintext page before requesting its keys. A following
		// record's KMS denial must not reject an otherwise readable page.
		records := result.Records[:0]
		bytes := 0
		for _, record := range result.Records {
			if record.Offset < page.NextOffset {
				continue
			}
			if record.Timestamp.Before(cutoff) {
				page.NextOffset = record.Offset + 1
				continue
			}
			size := recordPlaintextSize(&record)
			if includePartitionKeys {
				size += len(record.PartitionKey)
			}
			if len(records) != 0 && size > maxBytes-bytes {
				break
			}
			records = append(records, record)
			bytes += size
		}
		if err := s.decryptRecords(ctx, stream, records); err != nil {
			return page, err
		}
		page.Records = make(api.RecordList, len(records))
		for i, record := range records {
			data := api.Data(record.Data)
			if data == nil {
				data = api.Data{}
			}
			out := api.Record{Data: data, PartitionKey: new(api.PartitionKey(record.PartitionKey)), SequenceNumber: new(sequence.number(record.Offset)), ApproximateArrivalTimestamp: new(api.Timestamp(record.Timestamp))}
			if len(record.Metadata) != 0 {
				out.EncryptionType = new(api.EncryptionTypeKMS)
			}
			page.Records[i] = out
			page.Bytes += len(data) + len(record.PartitionKey)
			page.NextOffset = record.Offset + 1
			lastArrival = record.Timestamp
		}
		page.NextOffset = max(page.NextOffset, bounds.Start)
	}
	page.Closed = shard.State == ShardClosed && page.NextOffset >= bounds.End
	if page.Closed {
		page.ChildShards = childShards(shards, shard.Key.ID())
		lastArrival = shard.ClosedAt
	}
	if (page.NextOffset < bounds.End || page.Closed) && !lastArrival.IsZero() {
		page.MillisBehindLatest = max(int64(0), now.Sub(lastArrival).Milliseconds())
	}
	return page, nil
}

func childShards(shards []ShardRecord, parent string) api.ChildShardList {
	var children api.ChildShardList
	for _, shard := range shards {
		if shard.State == ShardOpening || (value(shard.Data.ParentShardId) != parent && value(shard.Data.AdjacentParentShardId) != parent) {
			continue
		}
		parents := api.ShardIdList{}
		if shard.Data.ParentShardId != nil {
			parents = append(parents, *shard.Data.ParentShardId)
		}
		if shard.Data.AdjacentParentShardId != nil {
			parents = append(parents, *shard.Data.AdjacentParentShardId)
		}
		children = append(children, api.ChildShard{ShardId: shard.Data.ShardId, ParentShards: parents, HashKeyRange: shard.Data.HashKeyRange})
	}
	return children
}
