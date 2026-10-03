package lambda

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"sync"
	"time"

	"stackd/compute/lambda/internal/telemetryapi"
)

type telemetryEvent struct {
	Time   string          `json:"time"`
	Type   string          `json:"type"`
	Record json.RawMessage `json:"record"`
}

type telemetrySubscriber struct {
	manager                      *telemetryManager
	name, api, key               string
	config                       telemetryConfig
	mu                           sync.Mutex
	pending                      []json.RawMessage
	bytes                        int
	first                        time.Time
	flush                        bool
	droppedRecords, droppedBytes uint64
	wake                         chan struct{}
	done                         chan struct{}
}

func newTelemetrySubscriber(m *telemetryManager, name, api, key string, config telemetryConfig) *telemetrySubscriber {
	return &telemetrySubscriber{manager: m, name: name, api: api, key: key, config: config, wake: make(chan struct{}, 1), done: make(chan struct{})}
}

func (s *telemetrySubscriber) accepts(kind string) bool {
	for _, filter := range s.config.types {
		if string(filter) == kind || (filter == "platform" && len(kind) > 9 && kind[:9] == "platform.") {
			return true
		}
	}
	return false
}

func (s *telemetrySubscriber) enqueueHistory(event telemetryEvent) {
	if !s.accepts(event.Type) || !slices.Contains(telemetryapi.Versions[s.config.version].Events, event.Type) {
		return
	}
	projected, err := projectTelemetryRecord(s.config.version, event.Type, event.Record)
	if err != nil {
		slog.Error("Lambda initialization telemetry projection failed", "type", event.Type, "error", err)
		return
	}
	event.Record = projected
	body, err := json.Marshal(event)
	if err != nil {
		slog.Error("Lambda initialization telemetry encoding failed", "type", event.Type, "error", err)
		return
	}
	s.enqueue(body)
}

func (s *telemetrySubscriber) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *telemetrySubscriber) enqueue(event json.RawMessage) {
	s.mu.Lock()
	// One independently bounded backlog per subscription, plus one in-flight
	// batch. The precise capacity/drop policy is local; AWS documents bounded
	// buffering and loss under backpressure, not an exact retry or loss schedule.
	// This manager runs in the execution container's PID 1. The queue and
	// in-flight delivery bytes are real allocations in the function cgroup.
	if len(s.pending) >= 2*s.config.maxItems || s.bytes+len(event) > 2*s.config.maxBytes {
		s.droppedRecords++
		s.droppedBytes += uint64(len(event))
	} else {
		if len(s.pending) == 0 {
			s.first = time.Now()
		}
		s.pending = append(s.pending, event)
		s.bytes += len(event)
	}
	s.mu.Unlock()
	s.notify()
}

func (s *telemetrySubscriber) flushPending() {
	s.mu.Lock()
	s.flush = true
	s.mu.Unlock()
	s.notify()
}

func (s *telemetrySubscriber) batch(now time.Time) ([]json.RawMessage, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 && s.droppedRecords == 0 {
		s.flush = false
		return nil, 0
	}
	remaining := time.Until(s.first.Add(s.config.timeout))
	if len(s.pending) != 0 && !s.flush && len(s.pending) < s.config.maxItems && s.bytes < s.config.maxBytes && remaining > 0 {
		return nil, remaining
	}
	count, size := 0, 0
	for count < len(s.pending) && count < s.config.maxItems {
		if count > 0 && size+len(s.pending[count]) > s.config.maxBytes {
			break
		}
		size += len(s.pending[count])
		count++
	}
	batch := slices.Clone(s.pending[:count])
	copy(s.pending, s.pending[count:])
	clear(s.pending[len(s.pending)-count:])
	s.pending = s.pending[:len(s.pending)-count]
	s.bytes -= size
	if len(s.pending) == 0 {
		s.first = time.Time{}
		s.flush = false
	}
	if s.droppedRecords > 0 && s.accepts("platform.logsDropped") && len(batch) < s.config.maxItems {
		record, err := json.Marshal(telemetryapi.PlatformLogsDropped{Reason: "Subscriber buffer full", DroppedRecords: s.droppedRecords, DroppedBytes: s.droppedBytes})
		if err == nil {
			event, eventErr := json.Marshal(telemetryEvent{Time: now.UTC().Format(time.RFC3339Nano), Type: "platform.logsDropped", Record: record})
			if eventErr == nil {
				batch = append(batch, event)
				s.droppedRecords = 0
				s.droppedBytes = 0
			}
		}
	} else if s.droppedRecords > 0 && !s.accepts("platform.logsDropped") {
		// A function-only subscription must not acquire platform membership.
		slog.Warn("Lambda telemetry records dropped", "extension", s.name, "records", s.droppedRecords, "bytes", s.droppedBytes)
		s.droppedRecords, s.droppedBytes = 0, 0
	}
	return batch, 0
}

func (s *telemetrySubscriber) run() {
	defer close(s.done)
	for {
		if s.manager.ctx.Err() != nil {
			return
		}
		batch, delay := s.batch(time.Now())
		if len(batch) > 0 {
			payload := telemetryPayload(s.config.destination.protocol, batch)
			if !s.deliver(payload) {
				return
			}
			continue
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if delay > 0 {
			timer = time.NewTimer(delay)
			timeout = timer.C
		}
		select {
		case <-s.manager.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-s.wake:
		case <-timeout:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func telemetryPayload(protocol string, records []json.RawMessage) []byte {
	size := 2
	for _, record := range records {
		size += len(record) + 1
	}
	payload := make([]byte, 0, size)
	if protocol == "HTTP" {
		payload = append(payload, '[')
	}
	for i, record := range records {
		if protocol == "HTTP" && i > 0 {
			payload = append(payload, ',')
		}
		payload = append(payload, record...)
		if protocol == "TCP" {
			payload = append(payload, '\n')
		}
	}
	if protocol == "HTTP" {
		payload = append(payload, ']')
	}
	return payload
}

func (s *telemetrySubscriber) deliver(payload []byte) bool {
	// AWS promises retries with backoff, not an exact attempt count or interval.
	// Retain the same bounded batch across listener failures and runtime resets.
	backoff := 25 * time.Millisecond
	failed := false
	for {
		ctx, cancel := context.WithTimeout(s.manager.ctx, 5*time.Second)
		err := s.manager.deliver(ctx, s.config.destination, payload)
		cancel()
		if err == nil {
			return true
		}
		if s.manager.ctx.Err() != nil {
			return false
		}
		if !failed {
			slog.Warn("Lambda telemetry delivery failed; retrying", "extension", s.name, "protocol", s.config.destination.protocol, "error", err)
			failed = true
		}
		timer := time.NewTimer(backoff)
		select {
		case <-s.manager.ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
		backoff = min(2*backoff, time.Second)
	}
}

func (m *telemetryManager) Emit(at time.Time, eventType string, record any) {
	body, err := json.Marshal(record)
	if err != nil {
		slog.Error("Lambda telemetry event encoding failed", "type", eventType, "error", err)
		return
	}
	m.emitRecord(at, eventType, body)
	m.renderPlatform(at, eventType, body)
}

func (m *telemetryManager) emitRecord(at time.Time, eventType string, body json.RawMessage) {
	if m.remote != nil {
		m.transfer(telemetryCommand{Operation: "emit", At: at, Kind: eventType, Body: body})
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	// Native initial deliveries include initStart and extension output emitted
	// before registration/subscription. Retain that finite initialization epoch,
	// not invocation history, and keep its original event timestamps.
	if eventType == "platform.initStart" {
		m.recordingInit = true
		m.history = nil
		m.historyBytes = 0
		m.historyDroppedRecords, m.historyDroppedBytes = 0, 0
	}
	if m.recordingInit {
		if uint64(len(m.history)) < telemetryapi.BufferingLimits["maxItems"].Default &&
			uint64(m.historyBytes+len(body)) <= 2*telemetryapi.BufferingLimits["maxBytes"].Default {
			m.history = append(m.history, telemetryEvent{Time: at.UTC().Format(time.RFC3339Nano), Type: eventType, Record: body})
			m.historyBytes += len(body)
		} else {
			m.historyDroppedRecords++
			m.historyDroppedBytes += uint64(len(body))
		}
	}
	if eventType == "platform.initReport" {
		m.recordingInit = false
		m.history = nil
		m.historyBytes = 0
		m.historyDroppedRecords, m.historyDroppedBytes = 0, 0
	}
	// Project and encode once per schema, not once per subscriber.
	encoded := make(map[telemetryapi.SchemaVersion]json.RawMessage)
	for _, subscriber := range m.subscribers {
		if !subscriber.accepts(eventType) {
			continue
		}
		version := subscriber.config.version
		if !slices.Contains(telemetryapi.Versions[version].Events, eventType) {
			continue
		}
		event, exists := encoded[version]
		if !exists {
			projected, err := projectTelemetryRecord(version, eventType, body)
			if err != nil {
				slog.Error("Lambda telemetry projection failed", "type", eventType, "schema", version, "error", err)
				continue
			}
			event, err = json.Marshal(telemetryEvent{Time: at.UTC().Format(time.RFC3339Nano), Type: eventType, Record: projected})
			if err != nil {
				slog.Error("Lambda telemetry encoding failed", "type", eventType, "error", err)
				continue
			}
			encoded[version] = event
		}
		subscriber.enqueue(event)
	}
}

func (m *telemetryManager) flush() {
	if m.remote != nil {
		m.transfer(telemetryCommand{Operation: "flush"})
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, subscriber := range m.subscribers {
		subscriber.flushPending()
	}
}

func (m *telemetryManager) Close() error {
	m.mu.Lock()
	streams := make([]*telemetryOutput, 0, len(m.streams))
	for stream := range m.streams {
		streams = append(streams, stream)
	}
	m.mu.Unlock()
	for _, stream := range streams {
		_ = stream.Close()
	}
	m.mu.Lock()
	m.closed = true
	subscribers := slices.Clone(m.subscribers)
	m.mu.Unlock()
	// The lifecycle owner closes this manager only after its shutdown window.
	// Do not extend customer shutdown or claim pending telemetry was delivered.
	m.cancel()
	for _, subscriber := range subscribers {
		<-subscriber.done
	}
	return nil
}

func (m *telemetryManager) transfer(command telemetryCommand) {
	if _, err := m.remote.call(m.ctx, command); err != nil && m.ctx.Err() == nil {
		m.remoteFailure(err)
	}
}
