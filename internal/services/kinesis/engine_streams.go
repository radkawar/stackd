package kinesis

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/kinesis"
)

// Lifecycle transitions need both their service-time boundary and actual native
// readiness. Advancing time cannot make a failed or absent broker ACTIVE.
const lifecycleDelay = time.Second

func (s *Service) reconcileStream(ctx context.Context, snapshot StreamRecord) (time.Time, error) {
	release, err := s.engines.lock(ctx, snapshot.EngineID)
	if err != nil {
		return time.Time{}, err
	}
	defer release()
	var stream StreamRecord
	err = s.repository.View(ctx, func(r Reader) error {
		var err error
		stream, err = r.Stream(snapshot.Key)
		return err
	})
	if errors.Is(err, ErrNotFound) || (err == nil && stream.EngineID != snapshot.EngineID) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	now := s.clock.Now()
	var transitionAt time.Time
	if stream.Pending != nil {
		transitionAt = stream.Pending.AcceptedAt.Add(lifecycleDelay)
	}
	if value(stream.Data.StreamStatus) == "DELETING" {
		if transitionAt.After(now) {
			return transitionAt, nil
		}
		s.consumers.cancelStream(stream.EngineID, now)
		if err := s.engines.forget(stream.EngineID); err != nil {
			return time.Time{}, err
		}
		if err := s.runtime.Remove(ctx, stream.Specification()); err != nil {
			return time.Time{}, err
		}
		return time.Time{}, s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Stream(stream.Key)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			if current.EngineID != stream.EngineID || value(current.Data.StreamStatus) != "DELETING" {
				return nil
			}
			return tx.DeleteStream(stream.Key)
		})
	}
	log, err := s.engines.log(ctx, stream.Specification())
	if err != nil {
		return time.Time{}, err
	}
	if value(stream.Data.StreamStatus) == "CREATING" || value(stream.Data.StreamStatus) == "UPDATING" {
		if err := log.EnsurePartitions(ctx, stream.NextPartition); err != nil {
			return time.Time{}, err
		}
		if transitionAt.After(s.clock.Now()) {
			return transitionAt, nil
		}
		// TODO: Comeback — model AWS's measured metadata-before-routing cutover;
		// this native-ready commit currently publishes both views together.
		err = s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Stream(stream.Key)
			if err != nil {
				return err
			}
			stream = current
			if current.EngineID != snapshot.EngineID || value(current.Data.StreamStatus) == "DELETING" {
				return nil
			}
			shards, err := tx.Shards(current.Key)
			if err != nil {
				return err
			}
			closed := make(map[string]bool)
			for _, shard := range shards {
				if shard.State == ShardOpening {
					if parent := value(shard.Data.ParentShardId); parent != "" {
						closed[parent] = true
					}
					if parent := value(shard.Data.AdjacentParentShardId); parent != "" {
						closed[parent] = true
					}
				}
			}
			at := s.clock.Now().UTC().Truncate(time.Millisecond)
			var count int32
			for _, shard := range shards {
				changed := false
				if shard.State == ShardOpening {
					shard.State, shard.OpenedAt = ShardOpen, at
					if shard.Data.ParentShardId == nil {
						shard.OpenedAt = *current.Data.StreamCreationTimestamp
					}
					changed = true
				}
				if shard.State == ShardOpen && closed[shard.Key.ID()] {
					shard.State, shard.ClosedAt = ShardClosed, at
					shard.Data.SequenceNumberRange.EndingSequenceNumber = new(sequenceFor(shard).end())
					changed = true
				}
				if shard.State == ShardOpen {
					count++
				}
				if changed {
					if err := tx.PutShard(shard); err != nil {
						return err
					}
				}
			}
			if current.Pending != nil {
				applyStreamUpdate(&current.Data, *current.Pending)
			}
			current.Data.OpenShardCount = new(api.ShardCountObject(count))
			current.Data.StreamStatus = new(api.StreamStatusACTIVE)
			current.Pending = nil
			// The first record cannot predate the stream. Before its initial
			// retention horizon there is no reason to scan native partitions.
			firstExpiry := current.Data.StreamCreationTimestamp.Add(time.Duration(*current.Data.RetentionPeriodHours) * time.Hour)
			current.RetentionNextAt = firstExpiry
			if !firstExpiry.After(at) {
				current.RetentionNextAt = at
			}
			if err := tx.PutStream(current); err != nil {
				return err
			}
			stream = current
			return nil
		})
		if err != nil {
			return time.Time{}, err
		}
		s.jobs.Wake()
	}
	if value(stream.Data.StreamStatus) == "DELETING" {
		return s.clock.Now(), nil
	}
	consumerDeadline, err := s.reconcileConsumers(ctx, stream, log)
	if err != nil {
		return time.Time{}, err
	}
	now = s.clock.Now()
	if stream.RetentionNextAt.After(now) {
		return earlierDeadline(consumerDeadline, stream.RetentionNextAt), nil
	}
	var shards []ShardRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		shards, err = r.Shards(stream.Key)
		return err
	}); err != nil {
		return time.Time{}, err
	}
	cutoff := now.Add(-time.Duration(*stream.Data.RetentionPeriodHours) * time.Hour)
	for _, shard := range shards {
		if shard.State == ShardOpening || !shard.OpenedAt.Before(cutoff) {
			continue
		}
		offset, err := log.OffsetAt(ctx, shard.Key.Partition, cutoff)
		if err != nil {
			return time.Time{}, err
		}
		if err := log.Trim(ctx, shard.Key.Partition, offset); err != nil {
			return time.Time{}, err
		}
	}
	next := now.Add(time.Minute)
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Stream(stream.Key)
		if err != nil {
			return err
		}
		if current.EngineID != stream.EngineID {
			return nil
		}
		current.RetentionNextAt = next
		return tx.PutStream(current)
	})
	return earlierDeadline(consumerDeadline, next), err
}

func applyStreamUpdate(data *api.StreamDescriptionSummary, update StreamUpdate) {
	if update.RetentionHours != 0 {
		data.RetentionPeriodHours = new(api.RetentionPeriodHours(update.RetentionHours))
	}
	if update.Mode != "" {
		data.StreamModeDetails = &api.StreamModeDetails{StreamMode: new(update.Mode)}
	}
	if update.MaxRecordSizeKiB != 0 {
		data.MaxRecordSizeInKiB = new(api.MaxRecordSizeInKiB(update.MaxRecordSizeKiB))
	}
	if update.EncryptionType != "" {
		data.EncryptionType = new(update.EncryptionType)
		data.KeyId = nil
		if update.EncryptionType == api.EncryptionTypeKMS {
			data.KeyId = new(api.KeyId(update.KeyID))
		}
	}
	if update.Monitoring != nil {
		data.EnhancedMonitoring = api.EnhancedMonitoringList{{ShardLevelMetrics: api.MetricsNameList(update.Monitoring)}}
	}
	if update.WarmMiBps != nil {
		data.WarmThroughput = &api.WarmThroughputObject{CurrentMiBps: new(api.NaturalIntegerObject(*update.WarmMiBps))}
	}
	if data.StreamModeDetails.StreamMode != nil && *data.StreamModeDetails.StreamMode == api.StreamModePROVISIONED {
		data.WarmThroughput = nil
	}
}
