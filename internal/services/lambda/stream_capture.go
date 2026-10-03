package lambda

import (
	"context"
	"errors"

	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge/eventpattern"
)

func (s *Service) captureStreamShard(ctx context.Context, mapping EventSourceMappingRecord, consumer streamConsumer, shard *StreamShardRecord, iterators map[string]string, filters []*eventpattern.Pattern) error {
	count, bytes := 0, 0
	idle := true
	for _, lane := range shard.Lanes {
		count += len(lane.Records)
		for _, record := range lane.Records {
			bytes += len(record.Payload)
		}
		if len(lane.Records) > 0 || !lane.WindowStart.IsZero() {
			idle = false
		}
	}
	if idle && len(shard.Lanes) != mapping.Settings.Stream.ParallelizationFactor {
		shard.Lanes = make([]StreamLane, mapping.Settings.Stream.ParallelizationFactor)
	}
	if !shard.ReadComplete && len(shard.Lanes) == mapping.Settings.Stream.ParallelizationFactor && count < 10000 && bytes < 5*1024*1024 {
		if err := s.captureStreamPage(ctx, mapping, consumer, shard, iterators, filters); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) captureStreamPage(ctx context.Context, mapping EventSourceMappingRecord, consumer streamConsumer, shard *StreamShardRecord, iterators map[string]string, filters []*eventpattern.Pattern) error {
	now := s.clock.Now()
	page, err := consumer.Read(ctx, mapping, shard, iterators[shard.Key.ShardID], now)
	if err != nil {
		var wire *awswire.Error
		if errors.As(err, &wire) {
			if wire.Code == "ExpiredIteratorException" || wire.Code == "TrimmedDataAccessException" {
				delete(iterators, shard.Key.ShardID)
			}
			if wire.Code == "TrimmedDataAccessException" {
				s.streamDiagnostic(mapping, wire)
				shard.Checkpoint = ""
				shard.StartingPositionTimestamp = now.Add(-shard.Retention)
				if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutStreamShard(*shard) }); err != nil {
					return err
				}
			}
		}
		return err
	}
	if len(page.Records) == 0 && shard.ReadComplete == page.Complete && (page.Checkpoint == "" || page.Checkpoint == shard.Checkpoint) {
		iterators[shard.Key.ShardID] = page.Iterator
		s.sourceMetric(mapping, metricSourcePolled, 0)
		return nil
	}
	filtered := 0
	for _, record := range page.Records {
		matches, err := matchesStreamRecordFilters(mapping, filters, record.Payload)
		if err != nil {
			return err
		}
		if matches {
			lane := streamLaneFor(record.ItemKey, len(shard.Lanes))
			shard.Lanes[lane].Records = append(shard.Lanes[lane].Records, record)
		} else {
			filtered++
		}
	}
	if page.Checkpoint != "" {
		shard.Checkpoint = page.Checkpoint
	}
	shard.ReadComplete = page.Complete
	// Queued records, page checkpoint and source metrics commit atomically. An
	// aggregate's entire deaggregated payload is retained before its source cursor.
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutStreamShard(*shard); err != nil {
			return err
		}
		if s.sourceMetricEnabled(mapping, metricSourcePolled) {
			samples := []MetricSample{{Name: metricSourcePolled, Value: float64(len(page.Records)), SampleCount: 1}}
			if len(filters) > 0 {
				samples = append(samples, MetricSample{Name: metricSourceFiltered, Value: float64(filtered), SampleCount: 1})
			}
			return stageSourceMetrics(tx, mapping, now, samples...)
		}
		return nil
	}); err != nil {
		return err
	}
	iterators[shard.Key.ShardID] = page.Iterator
	s.jobs.Wake()
	return nil
}
