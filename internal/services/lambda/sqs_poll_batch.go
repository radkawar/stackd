package lambda

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
)

type sqsReceivedRecord struct {
	record   sqsEventRecord
	encoded  []byte
	received time.Time
}

// Share one renewable execution-role session across this mapping's live polls.
// Function configuration is reread before each poll; changing its role replaces
// the consumer, while already issued batches retain their original authority.
func (state *sqsPollState) openConsumer(ctx context.Context, source SQSSource, function FunctionRecord, sourceARN string) (SQSConsumer, *awswire.Error) {
	state.sourceMu.Lock()
	defer state.sourceMu.Unlock()
	if state.sourceConsumer != nil && state.sourceFunction == function.Key && state.sourceRole == function.Role {
		return state.sourceConsumer, nil
	}
	consumer, wire := source.Open(ctx, function.Key, function.Role, sourceARN)
	if wire != nil {
		return nil, wire
	}
	state.sourceConsumer, state.sourceFunction, state.sourceRole = consumer, function.Key, function.Role
	return consumer, nil
}

func (s *Service) runSQSPoll(ctx context.Context, mapping EventSourceMappingRecord, state *sqsPollState) (result sqsPollCompletion) {
	var function FunctionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		mapping, err = r.EventSourceMapping(mapping.Key)
		if err != nil {
			return err
		}
		if mapping.State != "Enabled" {
			return context.Canceled
		}
		function, err = loadFunction(r, mapping.Function)
		return err
	})
	if err != nil {
		result.backoff = s.sqsSourceError(ctx, mapping, "Target", err)
		return
	}
	if function.State != "Active" {
		result.backoff = s.sqsSourceError(ctx, mapping, "Target", fmt.Errorf("function is not active: %s", function.State))
		return
	}
	consumer, wire := state.openConsumer(ctx, s.sqs, function, mapping.EventSourceARN)
	if wire != nil {
		result.backoff = s.sqsSourceError(ctx, mapping, "Open", wire)
		return
	}
	info, wire := consumer.Check(ctx)
	if wire != nil {
		result.backoff = s.sqsSourceError(ctx, mapping, "GetQueueAttributes", wire)
		return
	}
	patterns, filterError := s.mappingFilters(ctx, mapping, true)
	if filterError != nil {
		result.backoff = s.sqsSourceError(ctx, mapping, "Filter", filterError)
		return
	}
	filters, err := compileSQSFilters(patterns)
	if err != nil {
		result.backoff = s.sqsSourceError(ctx, mapping, "Filter", err)
		return
	}
	var batch, pending []sqsReceivedRecord
	batchBytes := len(`{"Records":[]}`)
	var windowEnd time.Time
	polls := 0
	for ctx.Err() == nil {
		if len(pending) == 0 {
			if len(batch) >= mapping.Settings.BatchSize || polls != 0 && (mapping.Settings.BatchingWindow == 0 || !s.clock.Now().Before(windowEnd)) {
				break
			}
			// Stop extending an old issued batch after a control change. Records
			// already received keep their issued settings; the next task refreshes.
			current := false
			err := s.repository.View(ctx, func(r Reader) error {
				v, err := r.EventSourceMapping(mapping.Key)
				if err != nil {
					return err
				}
				current = v.State == "Enabled" && v.Version == mapping.Version
				return nil
			})
			if err != nil || !current {
				break
			}
			if !s.waitSourceDeadline(ctx, state.limiter.reserve(s.clock.Now(), 0)) {
				return
			}
			wait := 20
			if polls != 0 && !windowEnd.IsZero() {
				wait = min(20, max(1, int((windowEnd.Sub(s.clock.Now())+time.Second-1)/time.Second)))
			}
			input := &sqsapi.ReceiveMessageInput{
				MaxNumberOfMessages:   new(sqsapi.NullableInteger(min(10, mapping.Settings.BatchSize-len(batch)))),
				WaitTimeSeconds:       new(sqsapi.NullableInteger(wait)),
				MessageAttributeNames: sqsapi.MessageAttributeNameList{"All"},
				// Lambda's event contains delivery metadata, not the queue's SSE flag.
				MessageSystemAttributeNames: sqsapi.MessageSystemAttributeList{
					"ApproximateFirstReceiveTimestamp", "ApproximateReceiveCount", "SenderId", "SentTimestamp",
					"SequenceNumber", "MessageGroupId", "MessageDeduplicationId", "AWSTraceHeader", "DeadLetterQueueSourceArn",
				},
			}
			deadline := time.Time{}
			if polls != 0 {
				deadline = windowEnd
			}
			output, wire := s.sqsReceive(ctx, consumer, input, deadline)
			if wire != nil {
				if ctx.Err() == nil && (deadline.IsZero() || s.clock.Now().Before(deadline)) {
					result.backoff = s.sqsSourceError(ctx, mapping, "ReceiveMessage", wire)
				}
				break
			}
			polledAt := s.clock.Now()
			polls++
			if windowEnd.IsZero() {
				windowEnd = polledAt.Add(mapping.Settings.BatchingWindow)
			}
			result.polled += len(output.Messages)
			s.sourceMetric(mapping, metricSourcePolled, len(output.Messages))
			var filtered []sqsEventRecord
			bytesRead := 0
			for _, message := range output.Messages {
				record := sqsRecord(mapping, message)
				encoded, err := sourceJSON(record)
				if err != nil {
					result.backoff = s.sqsSourceError(ctx, mapping, "EventEncoding", err)
					return
				}
				bytesRead += len(record.Body)
				for name, attribute := range message.MessageAttributes {
					bytesRead += len(name) + len(value(attribute.DataType)) + len(value(attribute.StringValue)) + len(attribute.BinaryValue)
				}
				matches, err := matchesSQSFilters(filters, record)
				if err != nil {
					result.backoff = s.sqsSourceError(ctx, mapping, "Filter", err)
					return
				}
				if !matches {
					filtered = append(filtered, record)
					continue
				}
				pending = append(pending, sqsReceivedRecord{record: record, encoded: encoded, received: polledAt})
			}
			if len(filters) != 0 {
				s.sourceMetric(mapping, metricSourceFiltered, len(filtered))
			}
			if len(filtered) != 0 && !s.deleteSQSRecords(ctx, mapping, consumer, filtered) {
				result.backoff = true
			}
			if bytesRead != 0 && !s.waitSourceDeadline(ctx, state.limiter.reserve(polledAt, bytesRead)) {
				return
			}
			if len(output.Messages) == 0 {
				break
			}
		}
		for len(pending) != 0 {
			record := pending[0]
			additional := len(record.encoded)
			if len(batch) != 0 {
				additional++
			}
			if batchBytes+additional > sourceEventLimit || len(batch) == mapping.Settings.BatchSize {
				if len(batch) == 0 {
					// SQS normally bounds a message to 1 MB, but JSON escaping can
					// exceed the invoke limit. Leave it for visibility/redrive.
					result.backoff = s.sqsSourceError(ctx, mapping, "Invoke", errors.New("event payload exceeds the synchronous 6 MB limit"))
					return
				}
				failed, backoff := s.invokeSQSRecords(ctx, mapping, consumer, info, batch)
				result.backoff = result.backoff || backoff
				if info.FIFO && len(failed) != 0 {
					pending = sqsUnblockedRecords(pending, batch, failed)
				}
				batch = nil
				batchBytes = len(`{"Records":[]}`)
				continue
			}
			batch = append(batch, record)
			batchBytes += additional
			pending = pending[1:]
		}
	}
	if len(batch) != 0 && ctx.Err() == nil {
		_, backoff := s.invokeSQSRecords(ctx, mapping, consumer, info, batch)
		result.backoff = result.backoff || backoff
	}
	return
}

// Only the receive deadline is canceled by a batching window. The helper is
// joined before returning, and uses the service clock, including manual clocks.
func (s *Service) sqsReceive(ctx context.Context, consumer SQSConsumer, input *sqsapi.ReceiveMessageInput, deadline time.Time) (*sqsapi.ReceiveMessageOutput, *awswire.Error) {
	if deadline.IsZero() {
		return consumer.Receive(ctx, input)
	}
	ctx, cancel := context.WithCancel(ctx)
	timer := s.clock.NewTimerAt(deadline)
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
		case <-timer.C():
			cancel()
		}
	}()
	defer func() { cancel(); timer.Stop(); <-done }()
	return consumer.Receive(ctx, input)
}

func sqsUnblockedRecords(pending, batch []sqsReceivedRecord, failed map[string]bool) []sqsReceivedRecord {
	groups := make(map[sqsapi.String]bool)
	for _, record := range batch {
		if failed[record.record.MessageID] {
			groups[record.record.Attributes["MessageGroupId"]] = true
		}
	}
	out := pending[:0]
	for _, record := range pending {
		if !groups[record.record.Attributes["MessageGroupId"]] {
			out = append(out, record)
		}
	}
	return out
}

func (s *Service) invokeSQSRecords(ctx context.Context, mapping EventSourceMappingRecord, consumer SQSConsumer, info SQSQueueInfo, batch []sqsReceivedRecord) (map[string]bool, bool) {
	var payload bytes.Buffer
	payload.WriteString(`{"Records":[`)
	records := make([]sqsEventRecord, len(batch))
	ids := make([]string, len(batch))
	allFailed := make(map[string]bool, len(batch))
	expires := batch[0].received.Add(time.Duration(info.VisibilitySeconds) * time.Second)
	for i, item := range batch {
		if i != 0 {
			payload.WriteByte(',')
		}
		payload.Write(item.encoded)
		records[i], ids[i], allFailed[item.record.MessageID] = item.record, item.record.MessageID, true
		if due := item.received.Add(time.Duration(info.VisibilitySeconds) * time.Second); due.Before(expires) {
			expires = due
		}
	}
	payload.WriteString(`]}`)
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return allFailed, false
		}
		// A manual-clock advance can pass the lease while waking a retry timer.
		// Never resume that retry with receipts whose visibility has expired.
		if attempt > 0 && !s.clock.Now().Before(expires) {
			return allFailed, true
		}
		s.sourceMetric(mapping, metricSourceInvoked, len(batch))
		ctx = s.sqsRecursionContext(ctx, mapping.Function.FunctionKey, records)
		invocation := s.invokeSourceBatch(ctx, mapping, payload.Bytes(), ids, "")
		output, wire := invocation.Output, invocation.Wire
		if wire != nil {
			s.sourceMetric(mapping, metricSourceFailed, len(batch))
			if !s.sqsSourceError(ctx, mapping, "Invoke", wire) {
				return allFailed, false
			}
			if wire.Code == "TooManyRequestsException" {
				s.sqsThrottleMapping(ctx, mapping.Key)
				// Keep only this live batch while throttled, bounded by its SQS
				// visibility lease. Expiry releases it, never deletes the message.
				due := s.clock.Now().Add(time.Second * time.Duration(1<<min(attempt, 5)))
				if due.Before(expires) && s.waitSourceDeadline(ctx, due) {
					continue
				}
			}
			return allFailed, true
		}
		failed := map[string]bool{}
		var responseError error
		if value(output.FunctionError) != "" {
			responseError = fmt.Errorf("function error: %s", value(output.FunctionError))
		} else if mapping.Settings.ReportBatchItemFailures {
			failed, responseError = sqsBatchFailures(output.Payload, records)
		}
		if responseError != nil {
			failed = allFailed
		}
		s.sourceMetric(mapping, metricSourceFailed, len(failed))
		if responseError != nil {
			s.sqsSourceError(ctx, mapping, "Invoke", responseError)
		}
		ack := records[:0]
		for _, record := range records {
			if !failed[record.MessageID] {
				ack = append(ack, record)
			}
		}
		// Disable stops polling, not acknowledgement of an accepted execution.
		deleted := true
		if len(ack) != 0 {
			deleted = s.deleteSQSRecords(s.lifetime, mapping, consumer, ack)
		}
		return failed, !deleted || responseError != nil && !mapping.Settings.ReportBatchItemFailures
	}
}

func (s *Service) deleteSQSRecords(ctx context.Context, mapping EventSourceMappingRecord, consumer SQSConsumer, records []sqsEventRecord) bool {
	success := true
	for start := 0; start < len(records); start += 10 {
		end := min(start+10, len(records))
		entries := make(sqsapi.DeleteMessageBatchRequestEntryList, 0, end-start)
		for i, record := range records[start:end] {
			entries = append(entries, sqsapi.DeleteMessageBatchRequestEntry{Id: new(sqsapi.String(strconv.Itoa(i))), ReceiptHandle: new(sqsapi.String(record.ReceiptHandle))})
		}
		output, wire := consumer.Delete(ctx, &sqsapi.DeleteMessageBatchInput{Entries: entries})
		deleted := 0
		if wire != nil {
			s.sqsSourceError(ctx, mapping, "DeleteMessageBatch", wire)
			success = false
		} else {
			deleted = len(output.Successful)
			if len(output.Failed) != 0 {
				success = false
				first := output.Failed[0]
				s.sqsSourceError(ctx, mapping, "DeleteMessageBatch", fmt.Errorf("%s: %s", value(first.Code), value(first.Message)))
			}
		}
		s.sourceMetric(mapping, metricSQSDeleted, deleted)
	}
	return success
}

func (s *Service) sqsSourceError(ctx context.Context, mapping EventSourceMappingRecord, operation string, err error) bool {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return false
	}
	slog.WarnContext(ctx, "Lambda SQS source operation failed", "mapping", mapping.Key.ARN(), "operation", operation, "error", err)
	return true
}
