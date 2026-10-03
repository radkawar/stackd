package lambda

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
)

// Lanes hash the DynamoDB item key or Kinesis partition key. Only one batch
// per lane is admitted at a time; a failed suffix stays ahead of later records.
func prepareStreamLane(mapping EventSourceMappingRecord, lane *StreamLane, readComplete bool, now time.Time) bool {
	if len(lane.Batches) > 0 {
		return !lane.Batches[0].Due.After(now)
	}
	settings := mapping.Settings.Stream
	if settings.TumblingWindow > 0 || !lane.WindowStart.IsZero() {
		if lane.WindowStart.IsZero() && len(lane.Records) > 0 {
			lane.WindowStart = lane.Records[0].CreatedAt.Truncate(settings.TumblingWindow)
			lane.WindowEnd = lane.WindowStart.Add(settings.TumblingWindow)
		}
		nextWindow := len(lane.Records) > 0 && !lane.Records[0].CreatedAt.Before(lane.WindowEnd)
		// Stream windows tolerate idle input for up to two minutes so delayed
		// source pages can still join their timestamp's window. The retained
		// boundary, not process wall time, also drives finalization after reopen.
		idleWindow := len(lane.Records) == 0 && !now.Before(lane.WindowEnd.Add(2*time.Minute))
		if !lane.WindowStart.IsZero() && (lane.WindowEarly || nextWindow || (readComplete || idleWindow) && len(lane.Records) == 0) {
			lane.WindowFinal = true
			lane.Batches = []StreamBatch{{Due: now, LastRequestID: uuid.NewString()}}
			return true
		}
	}
	if len(lane.Records) == 0 {
		return false
	}
	count, bytes := 0, len(`{"Records":[]}`)
	if !lane.WindowStart.IsZero() {
		bytes += len(lane.WindowState) + len(mapping.EventSourceARN) + 512
	}
	for _, record := range lane.Records {
		if !lane.WindowStart.IsZero() && !record.CreatedAt.Before(lane.WindowEnd) {
			break
		}
		if count == mapping.Settings.BatchSize {
			break
		}
		if bytes+len(record.Payload)+1 > sourceEventLimit {
			// Retain a singleton oversized batch so ordinary admission and
			// failure handling can discard it instead of pinning this lane forever.
			if count == 0 {
				count = 1
			}
			break
		}
		count++
		bytes += len(record.Payload) + 1
	}
	if count == 0 {
		return false
	}
	due := lane.Records[0].CapturedAt.Add(mapping.Settings.BatchingWindow)
	if !lane.WindowStart.IsZero() && lane.WindowEnd.Before(due) {
		due = lane.WindowEnd
	}
	if count < mapping.Settings.BatchSize && count == len(lane.Records) && !readComplete && now.Before(due) {
		return false
	}
	lane.Batches = []StreamBatch{{Count: count, Due: now, LastRequestID: uuid.NewString()}}
	return true
}

type streamLaneCompletion struct {
	index                    int
	lane                     StreamLane
	failures                 []StreamFailure
	result                   string
	invoked, failed, dropped int
	iteratorAge              time.Duration
}

func (s *Service) processStreamShard(ctx context.Context, mapping EventSourceMappingRecord, function FunctionRecord, shard *StreamShardRecord) error {
	now := s.clock.Now()
	ready := make([]int, 0, len(shard.Lanes))
	for i := range shard.Lanes {
		if prepareStreamLane(mapping, &shard.Lanes[i], shard.ReadComplete, now) {
			ready = append(ready, i)
		}
	}
	if len(ready) == 0 && !shard.ReadComplete {
		return nil
	}
	// Batch boundaries/window state exist before admission. A crash can repeat
	// customer execution, but can never skip the captured source record.
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutStreamShard(*shard) }); err != nil {
		return err
	}
	done := make(chan streamLaneCompletion, len(ready))
	for _, index := range ready {
		lane := shard.Lanes[index]
		// Other lane completions persist the shard while this worker mutates retries.
		lane.Batches = slices.Clone(lane.Batches)
		go func() {
			result := s.executeStreamLane(ctx, mapping, function, shard.Key.ShardID, shard.Retention, lane)
			result.index = index
			done <- result
		}()
	}
	var firstErr error
	for range ready {
		completion := <-done
		shard.Lanes[completion.index] = completion.lane
		if firstErr != nil {
			continue
		}
		// Poll cancellation does not revoke an already admitted execution or its
		// completion. Service shutdown may leave it replayable on reopen.
		err := s.repository.Update(s.lifetime, func(tx Transaction) error {
			stateErr := tx.PutStreamShard(*shard)
			if stateErr != nil && !errors.Is(stateErr, ErrNotFound) {
				return stateErr
			}
			for _, failure := range completion.failures {
				if err := tx.PutStreamFailure(failure); err != nil {
					return err
				}
			}
			if stateErr == nil && completion.result != "" {
				if err := tx.SetEventSourceMappingProcessingResult(mapping.Key, completion.result); err != nil {
					return err
				}
			}
			if s.sourceMetricEnabled(mapping, metricSourceInvoked) {
				var samples []MetricSample
				if completion.invoked > 0 {
					samples = append(samples,
						MetricSample{Name: metricSourceInvoked, Value: float64(completion.invoked), SampleCount: 1},
						MetricSample{Name: metricSourceFailed, Value: float64(completion.failed), SampleCount: 1})
				}
				if completion.dropped > 0 {
					samples = append(samples, MetricSample{Name: "DroppedEventCount", Value: float64(completion.dropped), SampleCount: 1})
				}
				if len(samples) > 0 {
					if err := stageSourceMetrics(tx, mapping, s.clock.Now(), samples...); err != nil {
						return err
					}
				}
			}
			if completion.invoked > 0 && s.metrics != nil {
				return s.stageMetricSamples(tx, mapping.Function, "", now, []MetricSample{{Name: "IteratorAge", Value: float64(completion.iteratorAge) / float64(time.Millisecond), SampleCount: 1}})
			}
			return nil
		})
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if err == nil {
			s.jobs.Wake()
		}
	}
	if firstErr != nil {
		return firstErr
	}
	if shard.ReadComplete {
		shard.Complete = true
		for _, lane := range shard.Lanes {
			if len(lane.Records) > 0 || len(lane.Batches) > 0 || !lane.WindowStart.IsZero() {
				shard.Complete = false
				break
			}
		}
		if err := s.repository.Update(s.lifetime, func(tx Transaction) error { return tx.PutStreamShard(*shard) }); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return nil
}
