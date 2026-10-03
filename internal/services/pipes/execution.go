package pipes

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	"stackd/internal/awsctx"
)

// Delivery owners can defer admission or constrain retries without exposing
// their protocol/status interpretation to the source retry engine.
type deliveryRetryHints interface {
	RetryDelay() time.Duration
	RetryStopped() bool
	AdmissionDeferred() bool
}

type pipeEffect struct {
	pipeID string
	cancel context.CancelFunc
}

func (s *Service) hasEffects(pipeID string) bool {
	s.effectsMu.Lock()
	defer s.effectsMu.Unlock()
	for _, effect := range s.effects {
		if effect.pipeID == pipeID {
			return true
		}
	}
	return false
}
func (s *Service) recoverEffects(ctx context.Context, p PipeRecord, work []Work) error {
	now := s.clock.Now()
	candidates := make(map[string]int)
	s.effectsMu.Lock()
	for i, w := range work {
		if w.Phase != "executing" || w.PipeID != p.ID {
			continue
		}
		effect, active := s.effects[w.ID]
		if !active {
			candidates[w.ID] = i
		} else if !w.Due.After(now) {
			effect.cancel()
		}
	}
	s.effectsMu.Unlock()
	if len(candidates) == 0 {
		return nil
	}
	var recovered []Work
	err := s.repository.Update(ctx, func(t Transaction) error {
		current, err := t.PipeByID(p.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != p.Version {
			return nil
		}
		rows, err := t.Work(p.ID)
		if err != nil {
			return err
		}
		for _, w := range rows {
			index, selected := candidates[w.ID]
			if !selected || w.Phase != "executing" || w.PipeID != p.ID {
				continue
			}
			original := work[index]
			if w.Attempts != original.Attempts || !w.Due.Equal(original.Due) {
				continue
			}
			// Completion can commit and remove the effect after the job's
			// snapshot. Only the current, still-executing attempt is orphaned.
			w.Phase, w.Due = "ready", now
			if err := t.PutWork(w); err != nil {
				return err
			}
			recovered = append(recovered, w)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// Publish readiness to this job only after the owning transaction commits.
	for _, w := range recovered {
		work[candidates[w.ID]] = w
	}
	return nil
}
func (s *Service) launch(ctx context.Context, p PipeRecord, batch []Work) error {
	claimed := false
	err := s.repository.Update(ctx, func(t Transaction) error {
		current, err := t.PipeByID(p.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != p.Version || current.State != "RUNNING" {
			return nil
		}
		rows, err := t.Work(p.ID)
		if err != nil {
			return err
		}
		ready := map[string]bool{}
		for _, w := range rows {
			ready[w.ID] = w.Phase == "ready"
		}
		for _, w := range batch {
			if !ready[w.ID] {
				return nil
			}
		}
		for _, w := range batch {
			w.Phase = "executing"
			w.Due = s.clock.Now().Add(5 * time.Minute)
			if err = t.PutWork(w); err != nil {
				return err
			}
		}
		current.Due = s.clock.Now()
		claimed = true
		return t.PutPipe(current)
	})
	if err != nil || !claimed {
		return err
	}
	effectCtx, cancel := context.WithCancel(s.lifetime)
	effectCtx = awsctx.WithMetadata(effectCtx, awsctx.FromContext(ctx))
	s.effectsMu.Lock()
	for _, w := range batch {
		s.effects[w.ID] = pipeEffect{pipeID: p.ID, cancel: cancel}
	}
	s.effectsDone.Add(1)
	s.effectsMu.Unlock()
	go func() {
		defer s.effectsDone.Done()
		defer cancel()
		if err := s.execute(effectCtx, p, batch); err != nil {
			slog.ErrorContext(effectCtx, "Pipes execution completion failed", "pipe", p.Key.ARN(), "error", err)
		}
		s.effectsMu.Lock()
		for _, w := range batch {
			delete(s.effects, w.ID)
		}
		s.effectsMu.Unlock()
		s.jobs.Wake()
	}()
	return nil
}

func (s *Service) execute(ctx context.Context, p PipeRecord, batch []Work) error {
	if isKafka(p.Source.Kind) {
		leased, release, err := s.kafkaLease(ctx, p, batch)
		if err != nil {
			failed := make(map[string]bool, len(batch))
			for _, w := range batch {
				failed[w.RecordID] = true
			}
			return s.completeAttempt(ctx, p, batch, failed, err)
		}
		defer release()
		ctx = leased
	}
	started := s.clock.Now()
	executionID := uuid.NewString()
	payloads := make([][]byte, 0, len(batch))
	delivered := batch
	if isKafka(p.Source.Kind) {
		delivered = make([]Work, 0, len(batch))
	}
	for _, w := range batch {
		if isKafka(p.Source.Kind) {
			if w.Filtered {
				continue
			}
			delivered = append(delivered, w)
		}
		payloads = append(payloads, w.Event)
	}
	initial, err := batchPayload(payloads)
	if err != nil {
		return err
	}
	s.logExecution(ctx, p, executionID, "EXECUTION_STARTED", "INFO", initial, nil, started)
	if p.EnrichmentARN != "" && len(payloads) > 0 {
		s.logExecution(ctx, p, executionID, "ENRICHMENT_STAGE_ENTERED", "INFO", nil, nil, started)
		payloads, err = s.transformStage(ctx, p, executionID, "ENRICHMENT", p.EnrichmentTemplate, payloads, started)
		if err == nil {
			events := make([]TargetEvent, len(payloads))
			for i, payload := range payloads {
				events[i] = TargetEvent{Input: delivered[i].Event, Payload: payload}
			}
			s.logExecution(ctx, p, executionID, "ENRICHMENT_INVOCATION_STARTED", "TRACE", nil, nil, started)
			response, rejected := s.targets.Enrich(ctx, p, events)
			if rejected != nil {
				err = rejected
				s.logExecution(ctx, p, executionID, "ENRICHMENT_INVOCATION_FAILED", "ERROR", nil, err, started)
			} else {
				s.logExecution(ctx, p, executionID, "ENRICHMENT_INVOCATION_SUCCEEDED", "TRACE", nil, nil, started)
				payloads, err = enrichmentPayloads(response)
			}
		}
		if err != nil {
			s.logExecution(ctx, p, executionID, "ENRICHMENT_STAGE_FAILED", "ERROR", nil, err, started)
		} else {
			body, _ := batchPayload(payloads)
			s.logExecution(ctx, p, executionID, "ENRICHMENT_STAGE_SUCCEEDED", "INFO", body, nil, started)
		}
	}
	skipped := len(payloads) == 0
	result := DeliveryResult{}
	if err == nil && !skipped {
		s.logExecution(ctx, p, executionID, "TARGET_STAGE_ENTERED", "INFO", nil, nil, started)
		events := make([]TargetEvent, len(payloads))
		for i, payload := range payloads {
			events[i].Input = payload
		}
		payloads, err = s.transformStage(ctx, p, executionID, "TARGET", value(p.Target.InputTemplate), payloads, started)
		if err == nil {
			s.logExecution(ctx, p, executionID, "TARGET_INVOCATION_STARTED", "TRACE", nil, nil, started)
			var rejected error
			for i, payload := range payloads {
				events[i].Payload = payload
			}
			out, wire := s.targets.Deliver(ctx, p, delivered, events, false)
			if wire != nil {
				rejected = wire
			}
			result, err = out, rejected
			stage, level := "TARGET_INVOCATION_SUCCEEDED", "TRACE"
			if err != nil {
				stage, level = "TARGET_INVOCATION_FAILED", "ERROR"
			} else if len(result.FailedIDs) > 0 {
				stage, level = "TARGET_INVOCATION_PARTIALLY_FAILED", "ERROR"
			}
			s.logExecution(ctx, p, executionID, stage, level, nil, err, started)
		}
		stage, level := "TARGET_STAGE_SUCCEEDED", "INFO"
		if err != nil {
			stage, level = "TARGET_STAGE_FAILED", "ERROR"
		} else if len(result.FailedIDs) > 0 {
			stage, level = "TARGET_STAGE_PARTIALLY_FAILED", "ERROR"
		}
		body, _ := batchPayload(payloads)
		s.logExecution(ctx, p, executionID, stage, level, body, err, started)
	} else if err == nil {
		s.logExecution(ctx, p, executionID, "TARGET_STAGE_SKIPPED", "TRACE", nil, nil, started)
	}
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	failed := map[string]bool{}
	for _, id := range result.FailedIDs {
		failed[id] = true
	}
	if err != nil {
		for _, w := range batch {
			failed[w.RecordID] = true
		}
	}
	// Ordered source checkpoints cannot advance beyond the first failed item.
	if p.Source.Kind != "sqs" || stringsFIFO(p) {
		seen := false
		for _, w := range batch {
			seen = seen || failed[w.RecordID]
			if seen {
				failed[w.RecordID] = true
			}
		}
	}
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	if e := s.completeAttempt(completion, p, batch, failed, err); e != nil {
		return e
	}
	stage, level := "EXECUTION_SUCCEEDED", "INFO"
	if err != nil {
		stage, level = "EXECUTION_FAILED", "ERROR"
	} else if len(failed) > 0 {
		stage, level = "EXECUTION_PARTIALLY_FAILED", "ERROR"
	}
	s.logExecution(completion, p, executionID, stage, level, nil, err, started)
	s.publishExecution(completion, p, batch, failed, err, skipped, s.clock.Now().Sub(started))
	return nil
}
func (s *Service) transformStage(ctx context.Context, p PipeRecord, id, stage, template string, payloads [][]byte, started time.Time) ([][]byte, error) {
	if template == "" {
		return payloads, nil
	}
	s.logExecution(ctx, p, id, stage+"_TRANSFORMATION_STARTED", "TRACE", nil, nil, started)
	transform, err := compileTemplate(template)
	if err == nil {
		for i := range payloads {
			payloads[i], err = transform.apply(payloads[i], p, s.clock.Now())
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		s.logExecution(ctx, p, id, stage+"_TRANSFORMATION_FAILED", "ERROR", nil, err, started)
	} else {
		body, _ := batchPayload(payloads)
		s.logExecution(ctx, p, id, stage+"_TRANSFORMATION_SUCCEEDED", "TRACE", body, nil, started)
	}
	return payloads, err
}
func (s *Service) completeAttempt(ctx context.Context, p PipeRecord, batch []Work, failed map[string]bool, failure error) error {
	if isKafka(p.Source.Kind) && (failure != nil || len(failed) > 0) {
		if failed == nil {
			failed = make(map[string]bool, len(batch))
		}
		for _, w := range batch {
			failed[w.RecordID] = true
		}
	}
	now := s.clock.Now()
	var minimumDelay time.Duration
	var admission, stopped, hinted bool
	if failure != nil {
		var hints deliveryRetryHints
		if errors.As(failure, &hints) {
			minimumDelay, admission, stopped = hints.RetryDelay(), hints.AdmissionDeferred(), hints.RetryStopped()
			hinted = true
		}
	}
	return s.repository.Update(ctx, func(t Transaction) error {
		current, err := t.PipeByID(p.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		stored, err := t.Work(p.ID)
		if err != nil {
			return err
		}
		known := make(map[string]Work, len(stored))
		for _, v := range stored {
			known[v.ID] = v
		}
		for _, original := range batch {
			v, ok := known[original.ID]
			if !ok || v.Phase != "executing" {
				continue
			}
			if !failed[v.RecordID] {
				v.Phase, v.Due, v.LastError = "ack", now, ""
			} else {
				if !admission {
					v.Attempts++
				}
				v.Phase = "ready"
				if isKafka(p.Source.Kind) {
					v.BatchLimit = int32(len(batch))
				}
				v.LastError = "Partial batch failure"
				if failure != nil {
					v.LastError = failure.Error()
				}
				delay := time.Duration(0)
				if !admission {
					delay = time.Second * time.Duration(min(60, 1<<min(v.Attempts, 6)))
				}
				v.Due = now.Add(max(delay, minimumDelay))
				if p.Source.Kind == "sqs" {
					// The queue owns visibility and redrive. A fresh Receive must renew the
					// receipt before retrying, including after an emulator restart.
					v.Phase, v.Due = "waiting", now.Add(minimumDelay)
				} else if stopped {
					v.Phase, v.Due = "dlq", now
				} else if !admission && p.Source.AutomaticBisect && len(batch) > 1 {
					v.BatchLimit = int32(max(1, len(batch)/2))
					v.Attempts--
					v.Due = now.Add(max(time.Second, minimumDelay))
				} else if p.Source.MaximumRetries >= 0 && v.Attempts > p.Source.MaximumRetries || p.Source.MaximumAge >= 0 && now.Sub(v.Created) >= time.Duration(p.Source.MaximumAge)*time.Second {
					v.Phase, v.Due = "dlq", now
				}
				if hinted && p.Source.Kind != "sqs" && p.Source.MaximumAge >= 0 && v.Phase == "ready" {
					deadline := v.Created.Add(time.Duration(p.Source.MaximumAge) * time.Second)
					if !v.Due.Before(deadline) {
						v.Phase, v.Due = "dlq", deadline
						if v.Due.Before(now) {
							v.Due = now
						}
					}
				}
			}
			if err = t.PutWork(v); err != nil {
				return err
			}
		}
		current.Due = now
		return t.PutPipe(current)
	})
}
