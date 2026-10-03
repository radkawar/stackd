package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var errStreamFunctionCall = errors.New("function call failed")

func (s *Service) executeStreamLane(ctx context.Context, mapping EventSourceMappingRecord, function FunctionRecord, shard string, retention time.Duration, lane StreamLane) streamLaneCompletion {
	result := streamLaneCompletion{lane: lane}
	batch := lane.Batches[0]
	records := lane.Records[:batch.Count]
	settings := mapping.Settings.Stream
	window := !lane.WindowStart.IsZero()
	now := s.clock.Now()
	maxAge := retention
	ageReason := streamRetentionExpired
	if settings.MaximumRecordAge >= 0 && settings.MaximumRecordAge <= maxAge {
		maxAge = settings.MaximumRecordAge
		ageReason = streamRecordAgeExceeded
	}
	if lane.WindowFinal && now.Sub(lane.WindowStart) >= maxAge {
		return s.discardStreamRecords(mapping, function, shard, result, 0, ageReason, batch.LastEventID)
	}
	expired := 0
	for _, record := range records {
		if now.Sub(record.CreatedAt) < maxAge {
			break
		}
		expired++
	}
	if expired > 0 {
		result = s.discardStreamRecords(mapping, function, shard, result, expired, ageReason, batch.LastEventID)
		return result
	}
	if settings.MaximumRetryAttempts >= 0 && batch.Attempts > settings.MaximumRetryAttempts {
		return s.discardStreamRecords(mapping, function, shard, result, batch.Count, streamRetryExhausted, batch.LastEventID)
	}
	if ctx.Err() != nil {
		return result
	}
	payload, err := streamPayload(records, lane, shard, mapping.EventSourceARN, window)
	if err != nil {
		result.result = streamProcessingResult(err)
		result.lane.Batches[0].Due = now.Add(time.Second)
		return result
	}
	ids := make([]string, len(records))
	for i, v := range records {
		ids[i] = v.ID
	}
	result.invoked = len(records)
	if len(records) > 0 {
		result.iteratorAge = max(0, now.Sub(records[len(records)-1].CreatedAt))
	}
	invocation := s.invokeSourceBatch(ctx, mapping, payload, ids, batch.LastRequestID)
	if !invocation.Accepted {
		// Admission throttles and infrastructure denial do not spend the function's
		// retry quota. Age still advances while this batch waits for real capacity.
		result.lane.Batches[0].Due = s.clock.Now().Add(time.Second)
		result.failed = len(records)
		if invocation.Wire != nil {
			result.result = streamProcessingResult(invocation.Wire)
			if invocation.Wire.Code == "RequestTooLargeException" {
				// Native stream mappings spend their retry quota on payload
				// rejection, despite never entering a customer runtime.
				result.lane.Batches[0].Attempts++
				if settings.MaximumRetryAttempts >= 0 && result.lane.Batches[0].Attempts > settings.MaximumRetryAttempts {
					return s.discardStreamRecords(mapping, function, shard, result, batch.Count, streamRetryExhausted, batch.LastEventID)
				}
			}
		}
		return result
	}
	result.lane.Batches[0].LastEventID = invocation.EventID
	result.lane.Batches[0].LastRequestID = invocation.RequestID
	result.lane.Batches[0].InvokeCount++
	if invocation.Output != nil {
		result.lane.Batches[0].ExecutedVersion = value(invocation.Output.ExecutedVersion)
		result.lane.Batches[0].FunctionError = value(invocation.Output.FunctionError)
	}
	result.result = "OK"
	lowest := 0
	var state json.RawMessage
	if invocation.Wire != nil {
		err = invocation.Wire
	} else if value(invocation.Output.FunctionError) != "" {
		err = errStreamFunctionCall
	} else {
		lowest = len(records)
		if mapping.Settings.ReportBatchItemFailures {
			lowest, err = streamBatchFailure(invocation.Output.Payload, records)
		}
		if err == nil && window {
			var response map[string]json.RawMessage
			err = json.Unmarshal(invocation.Output.Payload, &response)
			if err == nil {
				state = response["state"]
				var object map[string]json.RawMessage
				if len(state) == 0 {
					err = fmt.Errorf("tumbling response has no state")
				} else if e := json.Unmarshal(state, &object); e != nil || object == nil {
					err = fmt.Errorf("tumbling response state must be an object")
				}
			}
		}
	}
	if err != nil {
		lowest = 0
		result.result = streamProcessingResult(err)
	}
	if lowest == len(records) && err == nil {
		result.lane.Records = result.lane.Records[batch.Count:]
		result.lane.Batches = result.lane.Batches[1:]
		if window {
			if lane.WindowFinal {
				resetStreamWindow(&result.lane)
			} else if len(state) > 1024*1024 {
				result.lane.WindowState = state
				result.lane.WindowEarly = true
			} else {
				result.lane.WindowState = state
			}
		}
		return result
	}
	result.failed = len(records) - lowest
	if lowest > 0 {
		result.lane.Records = result.lane.Records[lowest:]
		// A partial acknowledgement establishes a new batch at the failed sequence.
		// Its retries reuse one request ID; the larger parent does not spend quota.
		result.lane.Batches[0] = StreamBatch{Count: batch.Count - lowest, Due: now, LastRequestID: uuid.NewString()}
		return result
	} else if settings.BisectBatchOnFunctionError && batch.Count > 1 {
		left := StreamBatch{Count: batch.Count / 2, Due: now, LastRequestID: uuid.NewString()}
		right := StreamBatch{Count: batch.Count - left.Count, Due: now, LastRequestID: uuid.NewString()}
		result.lane.Batches = append([]StreamBatch{left, right}, result.lane.Batches[1:]...)
		return result
	}
	result.lane.Batches[0].Attempts++
	result.lane.Batches[0].Due = s.clock.Now().Add(time.Second)
	if settings.MaximumRetryAttempts >= 0 && result.lane.Batches[0].Attempts > settings.MaximumRetryAttempts {
		return s.discardStreamRecords(mapping, function, shard, result, result.lane.Batches[0].Count, streamRetryExhausted, invocation.EventID)
	}
	return result
}
func resetStreamWindow(lane *StreamLane) {
	lane.WindowStart = time.Time{}
	lane.WindowEnd = time.Time{}
	lane.WindowState = nil
	lane.WindowFinal = false
	lane.WindowEarly = false
}
