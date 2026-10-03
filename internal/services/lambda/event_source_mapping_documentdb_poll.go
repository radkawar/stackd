package lambda

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

type documentDBPollingKernel struct {
	wake     chan struct{}
	done     chan EventSourceMappingKey
	mappings map[EventSourceMappingKey]documentDBMappingWorker
}
type documentDBMappingWorker struct {
	cancel  context.CancelFunc
	version uint64
}

func (s *Service) startDocumentDBPollingLocked() {
	if s.documentDB == nil {
		return
	}
	k := &documentDBPollingKernel{wake: make(chan struct{}, 1), done: make(chan EventSourceMappingKey, 128), mappings: make(map[EventSourceMappingKey]documentDBMappingWorker)}
	s.documentDBPoller = k
	s.work.Add(1)
	go func() { defer s.work.Done(); s.runDocumentDBPolling(k) }()
}
func (s *Service) runDocumentDBPolling(k *documentDBPollingKernel) {
	timer := s.clock.NewTimer(0)
	defer timer.Stop()
	defer func() {
		for _, w := range k.mappings {
			w.cancel()
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
				slog.Error("Lambda DocumentDB mapping discovery failed", "error", err)
			}
			timer.Reset(time.Second)
			continue
		}
		present := make(map[EventSourceMappingKey]bool, len(rows))
		for _, v := range rows {
			if v.Settings.DocumentDB == nil || v.State != "Enabled" {
				continue
			}
			present[v.Key] = true
			if worker, ok := k.mappings[v.Key]; ok {
				if worker.version != v.Version {
					worker.cancel()
				}
				continue
			}
			ctx, cancel := context.WithCancel(ownerContext(s.lifetime, v.Function.FunctionKey))
			s.mu.Lock()
			if s.closed.Load() {
				s.mu.Unlock()
				cancel()
				return
			}
			s.work.Add(1)
			s.mu.Unlock()
			k.mappings[v.Key] = documentDBMappingWorker{cancel: cancel, version: v.Version}
			go func(v EventSourceMappingRecord) {
				defer s.work.Done()
				defer cancel()
				s.runDocumentDBMapping(ctx, v.Key, v.Version)
				select {
				case k.done <- v.Key:
				case <-s.lifetime.Done():
				}
			}(v)
		}
		for key, worker := range k.mappings {
			if !present[key] {
				worker.cancel()
			}
		}
		timer.Reset(time.Second)
	}
}
func (s *Service) documentDBMappingTarget(ctx context.Context, key EventSourceMappingKey, version uint64) (mapping EventSourceMappingRecord, function FunctionRecord, checkpoint DocumentDBCheckpoint, err error) {
	err = s.repository.View(ctx, func(r Reader) error {
		var err error
		mapping, err = r.EventSourceMapping(key)
		if err != nil {
			return err
		}
		if mapping.Version != version || mapping.State != "Enabled" || mapping.Settings.DocumentDB == nil {
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
			return errors.New("DocumentDB requires a function timeout of no more than 840 seconds")
		}
		checkpoint, err = r.DocumentDBCheckpoint(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	})
	return
}

type documentDBPendingBatch struct {
	records          []json.RawMessage
	ids              []string
	next             []byte
	bytes, baseBytes int
	deadline, time   time.Time
	payload          []byte
	carry            *DocumentDBRecord
}

func documentDBEventPayload(mapping EventSourceMappingRecord, records []json.RawMessage) ([]byte, error) {
	return json.Marshal(struct {
		SourceARN string            `json:"eventSourceArn"`
		Events    []json.RawMessage `json:"events"`
		Source    string            `json:"eventSource"`
	}{mapping.EventSourceARN, records, "aws:docdb"})
}
func (s *Service) runDocumentDBMapping(ctx context.Context, key EventSourceMappingKey, version uint64) {
	var consumer DocumentDBConsumer
	var batch documentDBPendingBatch
	var role string
	var functionKey FunctionKey
	defer func() {
		if consumer != nil {
			_ = consumer.Close()
		}
	}()
	for ctx.Err() == nil {
		mapping, function, checkpoint, err := s.documentDBMappingTarget(ctx, key, version)
		if errors.Is(err, context.Canceled) || errors.Is(err, ErrNotFound) {
			return
		}
		if err == nil && consumer != nil && (role != function.Role || functionKey != function.Key) {
			_ = consumer.Close()
			consumer = nil
			batch = documentDBPendingBatch{}
		}
		if err == nil && consumer == nil {
			consumer, err = s.documentDB.Open(ctx, function.Key, function.Role, mapping, checkpoint)
			if err == nil {
				role, functionKey = function.Role, function.Key
				if checkpoint.Incarnation == "" {
					checkpoint = consumer.Position()
					checkpoint.Mapping = key
					err = s.commitDocumentDBPosition(ctx, mapping, checkpoint, false, time.Time{})
				}
			}
		}
		if err == nil {
			err = s.captureDocumentDBBatch(ctx, mapping, consumer, &batch)
		}
		if err == nil && (batch.payload != nil || len(batch.records) > 0 && !s.clock.Now().Before(batch.deadline)) {
			if batch.payload == nil {
				batch.payload, err = documentDBEventPayload(mapping, batch.records)
			}
			if err == nil {
				err = consumer.Check(ctx)
			}
			if err == nil {
				s.sourceMetric(mapping, metricSourceInvoked, len(batch.records))
				result := s.invokeSourceBatch(ctx, mapping, batch.payload, batch.ids, "")
				if result.Wire != nil {
					err = result.Wire
				} else if result.Output.FunctionError != nil {
					err = errors.New("Function returned an error")
				}
				if err != nil {
					s.sourceMetric(mapping, metricSourceFailed, len(batch.records))
					s.streamDiagnostic(mapping, err)
					// Keep exactly the failed batch and its uncommitted token. There is one
					// sequential invocation per mapping, including retries.
					if !s.waitSourceDeadline(ctx, s.clock.Now().Add(time.Second)) {
						return
					}
					continue
				}
			}
			if err == nil {
				checkpoint = consumer.Position()
				checkpoint.Mapping = key
				checkpoint.ResumeToken = batch.next
				err = consumer.Check(ctx)
				if err == nil {
					err = s.commitDocumentDBPosition(ctx, mapping, checkpoint, true, batch.time)
				}
				if err == nil {
					batch = documentDBPendingBatch{carry: batch.carry}
				}
			}
		} else if err == nil && len(batch.records) == 0 && len(batch.next) > 0 {
			// Oversized records are dropped, as on AWS. Advance only when no earlier
			// deliverable record is outstanding.
			checkpoint = consumer.Position()
			checkpoint.Mapping = key
			checkpoint.ResumeToken = batch.next
			err = consumer.Check(ctx)
			if err == nil {
				err = s.commitDocumentDBPosition(ctx, mapping, checkpoint, false, time.Time{})
			}
			if err == nil {
				batch = documentDBPendingBatch{carry: batch.carry}
			}
		}
		if err != nil && ctx.Err() == nil {
			s.streamDiagnostic(mapping, err)
			if errors.Is(err, ErrDocumentDBHistoryLost) || errors.Is(err, ErrDocumentDBStreamClosed) {
				s.disableDocumentDBMapping(ctx, mapping, err)
				return
			}
			if consumer != nil {
				_ = consumer.Close()
				consumer = nil
			}
			batch = documentDBPendingBatch{}
		}
		delay := 50 * time.Millisecond
		if err != nil {
			delay = time.Second
		}
		if !s.waitSourceDeadline(ctx, s.clock.Now().Add(delay)) {
			return
		}
	}
}
func (s *Service) captureDocumentDBBatch(ctx context.Context, mapping EventSourceMappingRecord, consumer DocumentDBConsumer, batch *documentDBPendingBatch) error {
	if batch.payload != nil || len(batch.records) > 0 && !s.clock.Now().Before(batch.deadline) {
		return nil
	}
	if batch.bytes == 0 {
		empty, err := documentDBEventPayload(mapping, []json.RawMessage{})
		if err != nil {
			return err
		}
		batch.baseBytes = len(empty)
		batch.bytes = batch.baseBytes
	}
	for polled := 0; polled < mapping.Settings.BatchSize && len(batch.records) < mapping.Settings.BatchSize; polled++ {
		if len(batch.records) > 0 && mapping.Settings.BatchingWindow > 0 && !s.clock.Now().Before(batch.deadline) {
			break
		}
		var record DocumentDBRecord
		if batch.carry != nil {
			record = *batch.carry
			batch.carry = nil
		} else {
			var found bool
			var err error
			record, found, err = consumer.Next(ctx)
			if err != nil {
				if errors.Is(err, ErrDocumentDBStreamClosed) && len(batch.records) > 0 {
					// Drain the final native batch before disabling the source.
					batch.deadline = s.clock.Now()
					return nil
				}
				return err
			}
			if !found {
				break
			}
			s.sourceMetric(mapping, metricSourcePolled, 1)
		}
		wrapped, err := json.Marshal(struct {
			Event json.RawMessage `json:"event"`
		}{record.Event})
		if err != nil {
			return err
		}
		if len(wrapped)+batch.baseBytes > sourceEventLimit {
			batch.next = record.ResumeToken
			if s.metrics != nil {
				err = s.repository.Update(ctx, func(tx Transaction) error {
					return s.stageMetricSamples(tx, mapping.Function, "", s.clock.Now(), []MetricSample{{Name: "OversizedRecordCount", Value: 1, SampleCount: 1}})
				})
				if err != nil {
					return err
				}
			}
			continue
		}
		additional := len(wrapped)
		if len(batch.records) > 0 {
			additional++
		}
		if batch.bytes+additional > sourceEventLimit {
			batch.carry = &record
			batch.deadline = s.clock.Now()
			break
		}
		if len(batch.records) == 0 {
			batch.deadline = s.clock.Now().Add(mapping.Settings.BatchingWindow)
		}
		batch.records = append(batch.records, wrapped)
		batch.ids = append(batch.ids, base64.StdEncoding.EncodeToString(record.ResumeToken))
		batch.next = record.ResumeToken
		batch.time = record.Time
		batch.bytes += additional
	}
	if len(batch.records) >= mapping.Settings.BatchSize {
		batch.deadline = s.clock.Now()
	}
	return nil
}
func (s *Service) commitDocumentDBPosition(ctx context.Context, mapping EventSourceMappingRecord, checkpoint DocumentDBCheckpoint, processed bool, latest time.Time) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.EventSourceMapping(mapping.Key)
		if err != nil {
			return err
		}
		if current.Version != mapping.Version || current.State != "Enabled" || current.Settings.DocumentDB == nil || current.Settings.DocumentDB.Incarnation != checkpoint.Incarnation {
			return context.Canceled
		}
		if err := tx.PutDocumentDBCheckpoint(checkpoint); err != nil {
			return err
		}
		if processed && s.metrics != nil && !latest.IsZero() {
			age := s.clock.Now().Sub(latest)
			if age < 0 {
				age = 0
			}
			if err := s.stageMetricSamples(tx, mapping.Function, "", s.clock.Now(), []MetricSample{{Name: "IteratorAge", Value: float64(age) / float64(time.Millisecond), SampleCount: 1}}); err != nil {
				return err
			}
		}
		if processed {
			return tx.SetEventSourceMappingProcessingResult(mapping.Key, "OK")
		}
		return nil
	})
}
func (s *Service) disableDocumentDBMapping(ctx context.Context, mapping EventSourceMappingRecord, cause error) {
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := tx.EventSourceMapping(mapping.Key)
		if err != nil {
			return err
		}
		if v.Version != mapping.Version {
			return nil
		}
		v.State = "Disabled"
		v.StateTransitionReason = cause.Error()
		v.Version++
		v.LastModified = s.clock.Now()
		v.TransitionAt = time.Time{}
		v.TransitionState = ""
		return tx.PutEventSourceMapping(v)
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("Lambda DocumentDB mapping disable failed", "error", err)
	}
	s.eventSourceMappingsChanged()
}
