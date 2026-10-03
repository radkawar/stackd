package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

type kafkaPollingKernel struct {
	wake     chan struct{}
	done     chan EventSourceMappingKey
	mappings map[EventSourceMappingKey]kafkaMappingWorker
}
type kafkaMappingWorker struct {
	cancel  context.CancelFunc
	version uint64
}

func (s *Service) startKafkaPollingLocked() {
	if s.kafka == nil {
		return
	}
	k := &kafkaPollingKernel{wake: make(chan struct{}, 1), done: make(chan EventSourceMappingKey, 128), mappings: make(map[EventSourceMappingKey]kafkaMappingWorker)}
	s.kafkaPoller = k
	s.work.Add(1)
	go func() { defer s.work.Done(); s.runKafkaPolling(k) }()
}
func (s *Service) runKafkaPolling(k *kafkaPollingKernel) {
	timer := s.clock.NewTimer(0)
	defer timer.Stop()
	defer func() {
		for _, worker := range k.mappings {
			worker.cancel()
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
		var rows []EventSourceMappingRecord
		err := s.repository.View(s.lifetime, func(r Reader) error { var err error; rows, err = r.AllEventSourceMappings(); return err })
		if err != nil {
			if s.lifetime.Err() == nil {
				slog.Error("Lambda MSK mapping discovery failed", "error", err)
			}
			timer.Reset(time.Second)
			continue
		}
		present := make(map[EventSourceMappingKey]bool, len(rows))
		for _, mapping := range rows {
			if mapping.Settings.Kafka == nil || mapping.State != "Enabled" {
				continue
			}
			present[mapping.Key] = true
			if worker, ok := k.mappings[mapping.Key]; ok {
				if worker.version != mapping.Version {
					worker.cancel()
				}
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
			k.mappings[mapping.Key] = kafkaMappingWorker{cancel: cancel, version: mapping.Version}
			go func(key EventSourceMappingKey, version uint64) {
				defer s.work.Done()
				defer cancel()
				s.runKafkaMapping(ctx, key, version)
				select {
				case k.done <- key:
				case <-s.lifetime.Done():
				}
			}(mapping.Key, mapping.Version)
		}
		for key, worker := range k.mappings {
			if !present[key] {
				worker.cancel()
			}
		}
		timer.Reset(time.Second)
	}
}
func (s *Service) kafkaMappingTarget(ctx context.Context, key EventSourceMappingKey, version uint64) (mapping EventSourceMappingRecord, function FunctionRecord, err error) {
	err = s.repository.View(ctx, func(r Reader) error {
		var err error
		mapping, err = r.EventSourceMapping(key)
		if err != nil {
			return err
		}
		if mapping.State != "Enabled" || mapping.Version != version || mapping.Settings.Kafka == nil {
			return context.Canceled
		}
		function, err = loadFunction(r, mapping.Function)
		if err != nil {
			return err
		}
		if function.State != "Active" {
			return fmt.Errorf("function is not active: %s", function.State)
		}
		if function.Timeout > 840 {
			return errors.New("MSK source requires a function timeout of no more than 840 seconds")
		}
		return nil
	})
	return
}

// bindKafkaIdentity commits the first successful broker observation before any
// fetch, offset commit or invocation. Unavailable topics do not prevent admission.
func (s *Service) bindKafkaIdentity(ctx context.Context, mapping EventSourceMappingRecord, identity KafkaIdentity) error {
	if identity.ClusterID == "" || identity.TopicID == "" {
		return errors.New("kafka source omitted the native cluster or topic identity")
	}
	if mapping.Settings.Kafka.Identity == identity {
		return nil
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.EventSourceMapping(mapping.Key)
		if err != nil {
			return err
		}
		if current.Version != mapping.Version || current.State != "Enabled" || current.Settings.Kafka == nil {
			return context.Canceled
		}
		if retained := current.Settings.Kafka.Identity; retained != (KafkaIdentity{}) {
			if retained != identity {
				return errors.New("kafka source cluster or topic identity changed")
			}
			return nil
		}
		current.Settings.Kafka.Identity = identity
		return tx.PutEventSourceMapping(current)
	})
}

type kafkaPendingBatch struct {
	ctx             context.Context
	cancel          context.CancelFunc
	start, next     int64
	deadline, retry time.Time
	records         []json.RawMessage
	ids             []string
	bytes           int
	payload         []byte
}

func clearKafkaBatches(batches map[int]*kafkaPendingBatch) {
	for partition, batch := range batches {
		batch.cancel()
		delete(batches, partition)
	}
}
func (s *Service) runKafkaMapping(ctx context.Context, key EventSourceMappingKey, version uint64) {
	var consumer KafkaConsumer
	var role string
	var functionKey FunctionKey
	var filters []kafkaMappingFilter
	filtersReady := false
	batches := make(map[int]*kafkaPendingBatch)
	defer func() {
		clearKafkaBatches(batches)
		if consumer != nil {
			_ = consumer.Close()
		}
	}()
	for ctx.Err() == nil {
		mapping, function, err := s.kafkaMappingTarget(ctx, key, version)
		if errors.Is(err, context.Canceled) || errors.Is(err, ErrNotFound) {
			return
		}
		if err == nil && (consumer == nil || role != function.Role || functionKey != function.Key) {
			clearKafkaBatches(batches)
			if consumer != nil {
				_ = consumer.Close()
				consumer = nil
			}
			consumer, err = s.kafka.Open(ctx, function.Key, function.Role, mapping)
			role, functionKey = function.Role, function.Key
			if err == nil {
				var identity KafkaIdentity
				identity, err = consumer.Identity(ctx)
				if err == nil {
					err = s.bindKafkaIdentity(ctx, mapping, identity)
				}
			}
		}
		if err == nil {
			patterns := mapping.Settings.Filters
			if mapping.Settings.EncryptedFilters != nil {
				values, wire := s.mappingFilters(ctx, mapping, true)
				if wire != nil {
					err = wire
				} else {
					patterns = values
				}
			}
			if err == nil && !filtersReady {
				filters, err = compileKafkaMappingFilters(patterns)
				filtersReady = err == nil
			}
		}
		if err == nil {
			err = s.pollKafkaMapping(ctx, mapping, consumer, batches, filters)
		}
		if err != nil && ctx.Err() == nil {
			s.streamDiagnostic(mapping, err)
			// The broker remains authoritative. Losing a lease discards ephemeral
			// buffers, never acknowledges them; retained native identity fences reopen.
			clearKafkaBatches(batches)
			if consumer != nil {
				_ = consumer.Close()
				consumer = nil
			}
		}
		delay := 250 * time.Millisecond
		if err != nil {
			delay = time.Second
		}
		if !s.waitSourceDeadline(ctx, s.clock.Now().Add(delay)) {
			return
		}
	}
}
func (s *Service) pollKafkaMapping(ctx context.Context, mapping EventSourceMappingRecord, consumer KafkaConsumer, batches map[int]*kafkaPendingBatch, filters []kafkaMappingFilter) error {
	partitions, err := consumer.Assignments(ctx)
	if err != nil {
		return err
	}
	bootstrap, err := consumer.BootstrapServers(ctx)
	if err != nil {
		return err
	}
	assigned := make(map[int]bool, len(partitions))
	for _, partition := range partitions {
		assigned[partition.ID] = true
		expired := partition.Offset < partition.FirstOffset
		if expired {
			s.streamDiagnostic(mapping, fmt.Errorf("kafka retention removed offsets [%d,%d) from partition %d", partition.Offset, partition.FirstOffset, partition.ID))
			partition.Offset = partition.FirstOffset
		}
		batch := batches[partition.ID]
		if batch != nil && (batch.ctx.Err() != nil || partition.Committed && partition.Offset > batch.start) {
			batch.cancel()
			delete(batches, partition.ID)
			batch = nil
		}
		if batch == nil {
			lease, cancel, err := consumer.Lease(ctx, partition.ID)
			if err != nil {
				return err
			}
			// Establish the initial position, or recover to the broker's actual log
			// start after retention. Neither acknowledges a surviving message. Persist
			// the start before fetching so LATEST cannot skip failed work on restart.
			if !partition.Committed || expired {
				if err := consumer.Commit(lease, map[int]int64{partition.ID: partition.Offset}); err != nil {
					cancel()
					return err
				}
			}
			batch = &kafkaPendingBatch{ctx: lease, cancel: cancel, start: partition.Offset, next: partition.Offset, bytes: len(mapping.EventSourceARN) + len(bootstrap) + len(mapping.Settings.Kafka.Topic) + 256}
			batches[partition.ID] = batch
		}
		if batch.payload == nil {
			if err := s.captureKafkaBatch(mapping, consumer, partition.ID, batch, filters); err != nil {
				return err
			}
		}
	}
	for partition, batch := range batches {
		if !assigned[partition] {
			batch.cancel()
			delete(batches, partition)
		}
	}
	type completion struct {
		partition int
		err       error
		complete  bool
	}
	ready := make([]int, 0, len(partitions))
	for _, partition := range partitions {
		batch := batches[partition.ID]
		if s.clock.Now().Before(batch.retry) {
			continue
		}
		if len(batch.records) == 0 {
			if batch.next > batch.start {
				if err := consumer.Commit(batch.ctx, map[int]int64{partition.ID: batch.next}); err != nil {
					return err
				}
				batch.cancel()
				delete(batches, partition.ID)
			}
			continue
		}
		if batch.payload == nil {
			if len(batch.records) < mapping.Settings.BatchSize && s.clock.Now().Before(batch.deadline) && batch.bytes < sourceEventLimit {
				continue
			}
			batch.payload, err = kafkaEventPayload(mapping, bootstrap, partition.ID, batch.records)
			if err != nil {
				return err
			}
		}
		ready = append(ready, partition.ID)
	}
	results := make(chan completion, len(ready))
	for _, partition := range ready {
		batch := batches[partition]
		go func(partition int, batch *kafkaPendingBatch) {
			if batch.ctx.Err() != nil {
				results <- completion{partition: partition, err: batch.ctx.Err()}
				return
			}
			s.sourceMetric(mapping, metricSourceInvoked, len(batch.records))
			invocation := s.invokeSourceBatch(batch.ctx, mapping, batch.payload, batch.ids, "")
			var err error
			if invocation.Wire != nil {
				err = invocation.Wire
			} else if invocation.Output.FunctionError != nil {
				err = errors.New("Function returned an error")
			}
			if err != nil {
				s.sourceMetric(mapping, metricSourceFailed, len(batch.records))
				s.streamDiagnostic(mapping, err)
				results <- completion{partition: partition}
				return
			}
			err = consumer.Commit(batch.ctx, map[int]int64{partition: batch.next})
			if err == nil {
				err = s.repository.Update(s.lifetime, func(tx Transaction) error { return tx.SetEventSourceMappingProcessingResult(mapping.Key, "OK") })
			}
			results <- completion{partition: partition, err: err, complete: err == nil}
		}(partition, batch)
	}
	var first error
	for range ready {
		result := <-results
		batch := batches[result.partition]
		if result.complete {
			batch.cancel()
			delete(batches, result.partition)
		} else {
			batch.retry = s.clock.Now().Add(time.Second)
		}
		if result.err != nil && first == nil {
			first = result.err
		}
	}
	return first
}
func (s *Service) captureKafkaBatch(mapping EventSourceMappingRecord, consumer KafkaConsumer, partition int, batch *kafkaPendingBatch, filters []kafkaMappingFilter) error {
	if len(batch.records) >= mapping.Settings.BatchSize || batch.bytes >= sourceEventLimit {
		return nil
	}
	page, err := consumer.Fetch(batch.ctx, partition, batch.next, mapping.Settings.BatchSize-len(batch.records))
	if err != nil {
		return err
	}
	s.sourceMetric(mapping, metricSourcePolled, len(page.Records))
	for _, record := range page.Records {
		encoded, err := kafkaRecordEvent(mapping.Settings.Kafka.Topic, record)
		if err != nil {
			return err
		}
		matched, err := matchesKafkaMappingFilters(filters, record, encoded)
		if err != nil {
			return err
		}
		if matched {
			if batch.bytes+len(encoded)+1 > sourceEventLimit {
				if len(batch.records) == 0 {
					return errors.New("kafka record exceeds the Lambda synchronous payload limit")
				}
				batch.bytes = sourceEventLimit
				return nil
			}
			if len(batch.records) == 0 {
				batch.deadline = s.clock.Now().Add(mapping.Settings.BatchingWindow)
			}
			batch.records = append(batch.records, json.RawMessage(encoded))
			batch.ids = append(batch.ids, fmt.Sprintf("%s-%d-%d", mapping.Settings.Kafka.Topic, partition, record.Offset))
			batch.bytes += len(encoded) + 1
		} else {
			s.sourceMetric(mapping, metricSourceFiltered, 1)
		}
		batch.next = record.Offset + 1
	}
	batch.next = page.NextOffset
	return nil
}
