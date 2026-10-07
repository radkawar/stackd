package lambda

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge/eventpattern"
)

type streamPollingKernel struct {
	wake     chan struct{}
	done     chan EventSourceMappingKey
	mappings map[EventSourceMappingKey]context.CancelFunc
}

func (s *Service) startStreamPollingLocked() {
	if s.dynamoDB == nil && s.kinesis == nil {
		return
	}
	k := &streamPollingKernel{wake: make(chan struct{}, 1), done: make(chan EventSourceMappingKey, 128), mappings: make(map[EventSourceMappingKey]context.CancelFunc)}
	s.streamPoller = k
	s.work.Add(2)
	go func() { defer s.work.Done(); s.runStreamPolling(k) }()
	go func() { defer s.work.Done(); s.runStreamDestinations() }()
}
func (s *Service) runStreamPolling(k *streamPollingKernel) {
	timer := s.clock.NewTimer(0)
	defer timer.Stop()
	defer func() {
		for _, cancel := range k.mappings {
			cancel()
		}
	}()
	for {
		select {
		case <-s.lifetime.Done():
			return
		case key := <-k.done:
			delete(k.mappings, key)
		case <-k.wake:
		case <-timer.C():
		}
		var mappings []EventSourceMappingRecord
		err := s.repository.View(s.lifetime, func(r Reader) error { var err error; mappings, err = r.AllEventSourceMappings(); return err })
		if err != nil {
			s.streamDiagnostic(EventSourceMappingRecord{}, err)
			timer.Reset(time.Second)
			continue
		}
		present := make(map[EventSourceMappingKey]bool, len(mappings))
		for _, mapping := range mappings {
			if mapping.Settings.Stream == nil || mapping.State != "Enabled" {
				continue
			}
			present[mapping.Key] = true
			if k.mappings[mapping.Key] != nil {
				continue
			}
			ctx, cancel := context.WithCancel(ownerContext(s.lifetime, mapping.Function.FunctionKey))
			s.mu.Lock()
			if s.closed.Load() {
				s.mu.Unlock()
				cancel()
				return
			}
			s.work.Add(1)
			s.mu.Unlock()
			k.mappings[mapping.Key] = cancel
			go func(key EventSourceMappingKey) {
				defer s.work.Done()
				defer cancel()
				s.runStreamMapping(ctx, key)
				select {
				case k.done <- key:
				case <-s.lifetime.Done():
				}
			}(mapping.Key)
		}
		for key, cancel := range k.mappings {
			if !present[key] {
				cancel()
			}
		}
		timer.Reset(time.Second)
	}
}

func (s *Service) runStreamMapping(ctx context.Context, key EventSourceMappingKey) {
	var consumer streamConsumer
	defer func() {
		if consumer != nil {
			consumer.Close()
		}
	}()
	var role string
	var functionKey FunctionKey
	var filterVersion uint64
	var filters []*eventpattern.Pattern
	iterators := make(map[string]string)
	for ctx.Err() == nil {
		mapping, function, err := s.streamMappingTarget(ctx, key)
		if errors.Is(err, ErrNotFound) {
			return
		}
		if errors.Is(err, context.Canceled) {
			return
		}
		if err == nil && (consumer == nil || role != function.Role || functionKey != function.Key) {
			var wire error
			if consumer != nil {
				consumer.Close()
				consumer = nil
			}
			opened, failure := s.openStreamConsumer(ctx, function, mapping.EventSourceARN)
			if failure != nil {
				wire = failure
			}
			if wire != nil {
				err = wire
			} else {
				consumer = opened
				role = function.Role
				functionKey = function.Key
				clear(iterators)
			}
		}
		var patterns []string
		if err == nil && mapping.Settings.EncryptedFilters != nil {
			var wire *awswire.Error
			patterns, wire = s.mappingFilters(ctx, mapping, true)
			if wire != nil {
				err = wire
			}
		} else {
			patterns = mapping.Settings.Filters
		}
		if err == nil && filterVersion != mapping.Version {
			filters, err = compileStreamFilters(patterns)
			if err == nil {
				filterVersion = mapping.Version
			}
		}
		if err == nil {
			err = s.pollStreamMapping(ctx, mapping, function, consumer, iterators, filters)
		}
		if errors.Is(err, ErrNotFound) {
			return
		}
		if err != nil && ctx.Err() == nil {
			if consumer != nil {
				consumer.Close()
				consumer = nil
			}
			clear(iterators)
			s.streamDiagnostic(mapping, err)
		}
		if !s.waitSourceDeadline(ctx, s.clock.Now().Add(250*time.Millisecond)) {
			return
		}
	}
}
func (s *Service) streamMappingTarget(ctx context.Context, key EventSourceMappingKey) (mapping EventSourceMappingRecord, function FunctionRecord, err error) {
	err = s.repository.View(ctx, func(r Reader) error {
		var err error
		mapping, err = r.EventSourceMapping(key)
		if err != nil {
			return err
		}
		if mapping.State != "Enabled" || mapping.Settings.Stream == nil {
			return context.Canceled
		}
		function, err = loadFunction(r, mapping.Function)
		if err != nil {
			return err
		}
		if function.State != "Active" {
			return fmt.Errorf("function is not active: %s", function.State)
		}
		return nil
	})
	return
}
func (s *Service) pollStreamMapping(ctx context.Context, mapping EventSourceMappingRecord, function FunctionRecord, consumer streamConsumer, iterators map[string]string, filters []*eventpattern.Pattern) error {
	var retained []StreamShardRecord
	if err := s.repository.View(ctx, func(r Reader) error { var err error; retained, err = r.StreamShards(mapping.Key); return err }); err != nil {
		return err
	}
	shards := make(map[string]*StreamShardRecord, len(retained))
	for i := range retained {
		shards[retained[i].Key.ShardID] = &retained[i]
	}
	description, err := consumer.Describe(ctx)
	if err != nil {
		return err
	}
	for _, shard := range shards {
		shard.Retention = description.Retention
	}
	discovered := description.Shards
	var newShards []StreamShardRecord
	for _, native := range discovered {
		id := native.ID
		if shards[id] != nil {
			continue
		}
		v := StreamShardRecord{Key: StreamShardKey{Mapping: mapping.Key, ShardID: id}, ParentID: native.ParentID, AdjacentParentID: native.AdjacentParentID, Retention: description.Retention, Lanes: make([]StreamLane, mapping.Settings.Stream.ParallelizationFactor)}
		if len(retained) == 0 {
			v.StartingPositionTimestamp = mapping.Settings.Stream.StartingPositionTimestamp
		}
		// Initial LATEST positions are captured for every shard before parent
		// draining; later descendants always start at their retained beginning.
		if len(retained) == 0 && mapping.Settings.Stream.StartingPosition == "LATEST" {
			sequence, wire := consumer.LatestSequence(ctx, id)
			if wire != nil {
				return wire
			}
			v.Checkpoint = sequence
		}
		newShards = append(newShards, v)
		shards[id] = &v
	}
	if len(newShards) > 0 {
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			for _, shard := range newShards {
				if err := tx.PutStreamShard(shard); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	// Capture source pages serially, then execute independent ready shards in
	// parallel. Parent eligibility is a snapshot: children are not admitted
	// until every parent's retained execution has completed in a prior pass.
	var ready []*StreamShardRecord
	var firstErr error
	for _, native := range discovered {
		shard := shards[native.ID]
		if shard.Complete || !streamParentsComplete(shard, shards) {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.captureStreamShard(ctx, mapping, consumer, shard, iterators, filters); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// A failed source read cannot suspend records already captured in
			// Lambda. Their retry/age limits and failure destinations still run
			// while the source recovers; only the capture cursor stays unchanged.
		}
		pending := shard.ReadComplete
		for _, lane := range shard.Lanes {
			pending = pending || len(lane.Records) > 0 || len(lane.Batches) > 0 || !lane.WindowStart.IsZero()
		}
		if pending {
			ready = append(ready, shard)
		}
	}
	// A shard that disappeared from the source cannot be silently marked complete:
	// retained customer work is still processed and the retention loss is visible.
	visible := make(map[string]bool, len(discovered))
	for _, v := range discovered {
		visible[v.ID] = true
	}
	for id, shard := range shards {
		if !visible[id] && !shard.Complete && streamParentsComplete(shard, shards) {
			s.streamDiagnostic(mapping, fmt.Errorf("stream retention lost shard %s", id))
			shard.ReadComplete = true
			ready = append(ready, shard)
		}
	}
	if len(ready) == 0 {
		return firstErr
	}
	done := make(chan error, len(ready))
	for _, shard := range ready {
		go func() { done <- s.processStreamShard(ctx, mapping, function, shard) }()
	}
	for range ready {
		if err := <-done; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func streamParentsComplete(shard *StreamShardRecord, shards map[string]*StreamShardRecord) bool {
	for _, id := range []string{shard.ParentID, shard.AdjacentParentID} {
		if parent := shards[id]; parent != nil && !parent.Complete {
			return false
		}
	}
	return true
}
func (s *Service) streamDiagnostic(mapping EventSourceMappingRecord, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	slog.Warn("Lambda stream source operation failed", "mapping", mapping.Key.ARN(), "error", err)
	if mapping.Key.UUID != "" {
		resultErr := s.repository.Update(s.lifetime, func(tx Transaction) error {
			return tx.SetEventSourceMappingProcessingResult(mapping.Key, streamProcessingResult(err))
		})
		if resultErr != nil && !errors.Is(resultErr, ErrNotFound) && !errors.Is(resultErr, context.Canceled) {
			slog.Error("Lambda stream result retention failed", "error", resultErr)
		}
	}
}

func streamProcessingResult(err error) string {
	if errors.Is(err, errStreamFunctionCall) {
		return "PROBLEM: Function call failed"
	}
	if errors.Is(err, errStreamSequence) {
		return "PROBLEM: Sequence number in function response is invalid. Please check function implementation."
	}
	var wire *awswire.Error
	if errors.As(err, &wire) {
		return "PROBLEM: " + wire.Message
	}
	return "PROBLEM: " + err.Error()
}
