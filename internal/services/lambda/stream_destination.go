package lambda

import (
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

type streamDiscardReason uint8

const (
	streamRetryExhausted streamDiscardReason = iota
	streamRecordAgeExceeded
	streamRetentionExpired
)

func (s *Service) discardStreamRecords(mapping EventSourceMappingRecord, function FunctionRecord, shard string, result streamLaneCompletion, count int, reason streamDiscardReason, parent string) streamLaneCompletion {
	batch := result.lane.Batches[0]
	records := result.lane.Records[:count]
	destination := mapping.Settings.Stream.OnFailure
	if destination != "" {
		condition := "RecordAgeExceeded"
		if reason == streamRetryExhausted {
			condition = "RetryAttemptsExhausted"
		}
		now := s.clock.Now()
		var functionError any
		if batch.FunctionError != "" {
			functionError = batch.FunctionError
		}
		info := map[string]any{"shardId": shard, "streamArn": mapping.EventSourceARN}
		if count > 0 {
			info["startSequenceNumber"] = records[0].Sequence
			info["endSequenceNumber"] = records[count-1].Sequence
			info["approximateArrivalOfFirstRecord"] = records[0].CreatedAt.UTC().Format(time.RFC3339Nano)
			info["approximateArrivalOfLastRecord"] = records[count-1].CreatedAt.UTC().Format(time.RFC3339Nano)
			info["batchSize"] = count
		}
		infoKey := "DDBStreamBatchInfo"
		if strings.Contains(mapping.EventSourceARN, ":kinesis:") {
			infoKey = "KinesisBatchInfo"
		}
		doc := map[string]any{
			"version": "1.0", "timestamp": now.UTC().Format("2006-01-02T15:04:05.000Z"),
			"requestContext": map[string]any{"requestId": batch.LastRequestID, "functionArn": mapping.Function.ARN(), "condition": condition, "approximateInvokeCount": max(1, batch.InvokeCount, batch.Attempts)},
			infoKey:          info,
		}
		if !result.lane.WindowStart.IsZero() {
			doc["timeWindowInfo"] = streamWindowMetadata(result.lane)
		}
		if batch.InvokeCount > 0 {
			doc["responseContext"] = map[string]any{"statusCode": 200, "executedVersion": batch.ExecutedVersion, "functionError": functionError}
		}
		if strings.Contains(destination, ":s3:::") {
			payload, err := streamPayload(records, result.lane, shard, mapping.EventSourceARN, !result.lane.WindowStart.IsZero())
			if err != nil {
				result.result = streamProcessingResult(err)
				result.lane.Batches[0].Due = now.Add(time.Second)
				return result
			}
			// S3 retains the complete original invocation payload; queue/topic failures
			// retain only stream metadata and never manufacture a second data plane.
			doc["payload"] = string(payload)
		}
		payload, err := sourceJSON(doc)
		if err != nil {
			result.result = streamProcessingResult(err)
			result.lane.Batches[0].Due = now.Add(time.Second)
			return result
		}
		result.failures = append(result.failures, StreamFailure{ID: uuid.NewString(), Mapping: mapping.Key, Function: mapping.Function, RoleARN: function.Role, DestinationARN: destination, ShardID: shard, RecordCount: count, CreatedAt: now, ParentEventID: parent, Payload: payload})
	}
	if destination == "" && reason != streamRetentionExpired {
		result.dropped += count
	}
	result.lane.Records = result.lane.Records[count:]
	result.lane.Batches[0].Count -= count
	if result.lane.Batches[0].Count == 0 {
		result.lane.Batches = result.lane.Batches[1:]
		if result.lane.WindowFinal {
			resetStreamWindow(&result.lane)
		}
	}
	return result
}
func (s *Service) runStreamDestinations() {
	for s.lifetime.Err() == nil {
		if s.streamTargets != nil {
			var failures []StreamFailure
			err := s.repository.View(s.lifetime, func(r Reader) error { var err error; failures, err = r.StreamFailures(); return err })
			if err != nil {
				s.streamDiagnostic(EventSourceMappingRecord{}, err)
			}
			for _, failure := range failures {
				if err := s.deliverStreamFailure(failure); err != nil {
					s.streamDiagnostic(EventSourceMappingRecord{}, err)
				}
			}
		}
		if !s.waitSourceDeadline(s.lifetime, s.clock.Now().Add(time.Second)) {
			return
		}
	}
}

func (s *Service) deliverStreamFailure(failure StreamFailure) error {
	ctx := ownerContext(s.lifetime, failure.Function.FunctionKey)
	wire := s.streamTargets.SendStream(ctx, failure)
	if err := ctx.Err(); err != nil {
		return err
	}
	if wire != nil {
		slog.WarnContext(ctx, "Lambda stream destination delivery failed", "mapping", failure.Mapping.ARN(), "destination", failure.DestinationARN, "error", wire)
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		now := s.clock.Now()
		name := "OnFailureDestinationDeliveredEventCount"
		if wire != nil {
			name = "DroppedEventCount"
			if err := s.stageMetric(tx, failure.Function, now, metricDestinationFailures, 1); err != nil {
				return err
			}
		}
		mapping, err := tx.EventSourceMapping(failure.Mapping)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil && s.sourceMetricEnabled(mapping, name) {
			if err := stageSourceMetrics(tx, mapping, now, MetricSample{Name: name, Value: float64(failure.RecordCount), SampleCount: 1}); err != nil {
				return err
			}
		}
		// A completed destination command is terminal, including provider denial.
		// Shutdown or transaction failure can leave an at-least-once replay.
		return tx.DeleteStreamFailure(failure.ID)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return err
}
