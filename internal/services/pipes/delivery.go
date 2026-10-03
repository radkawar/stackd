package pipes

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	sqsapi "stackd/internal/awsapi/sqs"
	"time"
)

func (s *Service) ack(ctx context.Context, p PipeRecord, batch []Work, checkpoints []Checkpoint) error {
	failed := map[string]bool{}
	if isKafka(p.Source.Kind) {
		if err := s.commitKafka(ctx, p, batch); err != nil {
			return s.delay(ctx, p, err.Error())
		}
	}
	if p.Source.Kind == "sqs" {
		consumer, err := s.sources.SQS(ctx, p)
		if err != nil {
			return s.delay(ctx, p, err.Error())
		}
		in := &sqsapi.DeleteMessageBatchInput{}
		for _, w := range batch {
			in.Entries = append(in.Entries, sqsapi.DeleteMessageBatchRequestEntry{Id: new(sqsapi.String(w.ID)), ReceiptHandle: new(sqsapi.String(w.Receipt))})
		}
		out, err := consumer.Delete(ctx, in)
		if err != nil {
			return s.delay(ctx, p, err.Error())
		}
		for _, failure := range out.Failed {
			failed[value(failure.Id)] = true
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
		for _, w := range batch {
			if failed[w.ID] {
				w.Due = s.clock.Now().Add(time.Second)
				if err = t.PutWork(w); err != nil {
					return err
				}
				continue
			}
			if err = t.DeleteWork(w.ID); err != nil {
				return err
			}
		}
		for _, checkpoint := range checkpoints {
			for _, w := range batch {
				if w.ShardID == checkpoint.ShardID && !failed[w.ID] {
					checkpoint.Sequence = w.Sequence
				}
			}
			if err = t.PutCheckpoint(checkpoint); err != nil {
				return err
			}
		}
		current.Due = s.clock.Now()
		return t.PutPipe(current)
	})
}
func (s *Service) deadLetter(ctx context.Context, p PipeRecord, batch []Work) error {
	result := DeliveryResult{}
	var rejected error
	if p.Source.DLQ != "" {
		events := make([]TargetEvent, len(batch))
		for i, w := range batch {
			body, err := json.Marshal(map[string]any{
				"version":         "1.0",
				"timestamp":       s.clock.Now(),
				"requestContext":  map[string]any{"pipeArn": p.Key.ARN(), "condition": "RetryAttemptsExhausted", "approximateInvokeCount": w.Attempts},
				"responseContext": map[string]any{"errorMessage": w.LastError},
				"requestPayload":  json.RawMessage(w.Event),
			})
			if err != nil {
				return err
			}
			events[i] = TargetEvent{Input: w.Event, Payload: body}
		}
		out, err := s.targets.Deliver(ctx, p, batch, events, true)
		result = out
		if err != nil {
			rejected = err
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
		for _, w := range batch {
			if rejected == nil && !slices.Contains(result.FailedIDs, w.RecordID) {
				w.Phase, w.Due = "ack", s.clock.Now()
			} else {
				w.Due = s.clock.Now().Add(time.Second)
			}
			if err = t.PutWork(w); err != nil {
				return err
			}
		}
		current.Due = s.clock.Now()
		return t.PutPipe(current)
	})
}
