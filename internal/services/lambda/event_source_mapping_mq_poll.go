package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"
)

type mqPollingKernel struct {
	wake     chan struct{}
	done     chan EventSourceMappingKey
	mappings map[EventSourceMappingKey]kafkaMappingWorker
}

func (s *Service) startMQPollingLocked() {
	if s.mq == nil {
		return
	}
	k := &mqPollingKernel{wake: make(chan struct{}, 1), done: make(chan EventSourceMappingKey, 128), mappings: map[EventSourceMappingKey]kafkaMappingWorker{}}
	s.mqPoller = k
	s.work.Add(1)
	go func() { defer s.work.Done(); s.runMQPolling(k) }()
}
func (s *Service) runMQPolling(k *mqPollingKernel) {
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
		err := s.repository.View(s.lifetime, func(r Reader) error { var e error; rows, e = r.AllEventSourceMappings(); return e })
		if err != nil {
			if s.lifetime.Err() == nil {
				slog.Error("Lambda MQ mapping discovery failed", "error", err)
			}
			timer.Reset(time.Second)
			continue
		}
		present := map[EventSourceMappingKey]bool{}
		for _, mapping := range rows {
			if mapping.Settings.MQ == nil || mapping.State != "Enabled" {
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
				s.runMQMapping(ctx, key, version)
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
func (s *Service) mqMappingTarget(ctx context.Context, key EventSourceMappingKey, version uint64) (mapping EventSourceMappingRecord, function FunctionRecord, err error) {
	err = s.repository.View(ctx, func(r Reader) error {
		var e error
		mapping, e = r.EventSourceMapping(key)
		if e != nil {
			return e
		}
		if mapping.Settings.MQ == nil || mapping.State != "Enabled" || mapping.Version != version {
			return context.Canceled
		}
		function, e = loadFunction(r, mapping.Function)
		if e != nil {
			return e
		}
		if function.State != "Active" {
			return errors.New("MQ target function is not active")
		}
		if function.Timeout > 840 {
			return errors.New("MQ source requires a function timeout of at most 840 seconds")
		}
		return nil
	})
	return
}
func (s *Service) runMQMapping(ctx context.Context, key EventSourceMappingKey, version uint64) {
	var consumer MQConsumer
	var role string
	var functionKey FunctionKey
	var pending []MQMessage
	var filters []kafkaMappingFilter
	filtersReady := false
	closeConsumer := func() {
		if consumer != nil {
			_ = consumer.Close()
			consumer = nil
		}
		pending = nil
	}
	defer closeConsumer()
	for ctx.Err() == nil {
		mapping, function, err := s.mqMappingTarget(ctx, key, version)
		if errors.Is(err, context.Canceled) || errors.Is(err, ErrNotFound) {
			return
		}
		if err == nil && (consumer == nil || role != function.Role || functionKey != function.Key) {
			closeConsumer()
			consumer, err = s.mq.Open(ctx, function.Key, function.Role, mapping)
			role, functionKey = function.Role, function.Key
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
				filters, err = compileMQMappingFilters(patterns)
				filtersReady = err == nil
			}
		}
		if err == nil {
			pending, err = s.pollMQBatch(ctx, mapping, role, consumer, pending, filters)
		}
		if err != nil && ctx.Err() == nil {
			s.streamDiagnostic(mapping, err)
			closeConsumer()
		}
		delay := 100 * time.Millisecond
		if err != nil {
			delay = time.Second
		}
		if !s.waitSourceDeadline(ctx, s.clock.Now().Add(delay)) {
			return
		}
	}
}
func (s *Service) pollMQBatch(ctx context.Context, mapping EventSourceMappingRecord, role string, consumer MQConsumer, pending []MQMessage, filters []kafkaMappingFilter) ([]MQMessage, error) {
	records := make([]json.RawMessage, 0, min(mapping.Settings.BatchSize, 100))
	ids := make([]string, 0, cap(records))
	count := 0
	envelope, err := mqEventPayload(mapping, records)
	if err != nil {
		return pending, err
	}
	bytes := len(envelope)
	deadline := time.Time{}
	for ctx.Err() == nil && count < mapping.Settings.BatchSize {
		if count == len(pending) {
			page, e := consumer.Fetch(ctx, min(100, mapping.Settings.BatchSize-count))
			if e != nil {
				return pending, e
			}
			pending = append(pending, page...)
			if len(page) == 0 {
				if deadline.IsZero() || !s.clock.Now().Before(deadline) {
					break
				}
				if !s.waitSourceDeadline(ctx, mqEarlierDeadline(deadline, s.clock.Now().Add(100*time.Millisecond))) {
					return pending, ctx.Err()
				}
				continue
			}
		}
		message := pending[count]
		match, e := matchesKafkaMappingFilters(filters, KafkaRecord{Value: message.Data}, []byte("{}"))
		if e != nil {
			return pending, e
		}
		if match {
			recordBytes := len(message.Record)
			if len(records) != 0 {
				recordBytes++
			}
			if bytes+recordBytes > sourceEventLimit {
				if len(records) == 0 {
					return pending, errors.New("MQ message exceeds the Lambda invocation payload limit")
				}
				break
			}
			records = append(records, message.Record)
			ids = append(ids, message.ID)
			bytes += recordBytes
			if deadline.IsZero() {
				deadline = s.clock.Now().Add(mapping.Settings.BatchingWindow)
			}
		} else {
			s.sourceMetric(mapping, metricSourceFiltered, 1)
		}
		count++
		s.sourceMetric(mapping, metricSourcePolled, 1)
		if !deadline.IsZero() && !s.clock.Now().Before(deadline) {
			break
		}
	}
	if count == 0 {
		return pending, nil
	}
	if len(records) > 0 {
		payload, e := mqEventPayload(mapping, records)
		if e != nil {
			return pending, e
		}
		if len(payload) > sourceEventLimit {
			return pending, errors.New("MQ batch exceeds the Lambda invocation payload limit")
		}
		for ctx.Err() == nil {
			// Recheck role/secret/network authority before every retry, without replacing
			// the native unacknowledged session or acknowledging a failed invocation.
			if _, e = consumer.Identity(ctx); e != nil {
				return pending, e
			}
			_, function, e := s.mqMappingTarget(ctx, mapping.Key, mapping.Version)
			if e != nil {
				return pending, e
			}
			if function.Role != role {
				return pending, errors.New("MQ function execution role changed")
			}
			s.sourceMetric(mapping, metricSourceInvoked, len(records))
			result := s.invokeSourceBatch(ctx, mapping, payload, ids, "")
			if result.Wire == nil && result.Output.FunctionError == nil {
				break
			}
			s.sourceMetric(mapping, metricSourceFailed, len(records))
			if result.Wire != nil {
				s.streamDiagnostic(mapping, result.Wire)
			} else {
				s.streamDiagnostic(mapping, errors.New("Function returned an error"))
			}
			if !s.waitSourceDeadline(ctx, s.clock.Now().Add(time.Second)) {
				return pending, ctx.Err()
			}
		}
	}
	if ctx.Err() != nil {
		return pending, ctx.Err()
	}
	_, function, err := s.mqMappingTarget(ctx, mapping.Key, mapping.Version)
	if err != nil {
		return pending, err
	}
	if function.Role != role {
		return pending, errors.New("MQ function execution role changed before acknowledgment")
	}
	if err = consumer.Acknowledge(ctx, count); err != nil {
		return pending, err
	}
	if err = s.repository.Update(ctx, func(t Transaction) error { return t.SetEventSourceMappingProcessingResult(mapping.Key, "OK") }); err != nil {
		return pending, err
	}
	clear(pending[:count])
	return pending[count:], nil
}
func mqEarlierDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
