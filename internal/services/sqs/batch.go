package sqs

import (
	"net/http"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
)

func (s *Service) registerBatch() {
	register(s, "SendMessageBatch", true, s.sendBatch)
	register(s, "DeleteMessageBatch", true, s.deleteBatch)
	register(s, "ChangeMessageVisibilityBatch", true, s.visibilityBatch)
}
func validateBatch(ids []string) *awswire.Error {
	if len(ids) == 0 {
		return failure("EmptyBatchRequest", "The batch request must contain at least one entry.")
	}
	if len(ids) > 10 {
		return failure("TooManyEntriesInBatchRequest", "The batch request must contain at most 10 entries.")
	}
	seen := make(map[string]bool)
	for _, id := range ids {
		if len(id) == 0 || len(id) > 80 || !queueNamePattern.MatchString(id) {
			return failure("InvalidBatchEntryId", "A batch entry ID is invalid.")
		}
		if seen[id] {
			return failure("BatchEntryIdsNotDistinct", "Batch entry IDs must be distinct.")
		}
		seen[id] = true
	}
	return nil
}
func batchError(id *api.String, err *awswire.Error) api.BatchResultErrorEntry {
	return api.BatchResultErrorEntry{Id: id, Code: str(err.Code), Message: str(err.Message), SenderFault: ptr(api.Boolean(err.StatusCode < 500))}
}
func (s *Service) sendBatch(r *http.Request, in *api.SendMessageBatchInput) (result *api.SendMessageBatchOutput, wireErr *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	defer func() {
		if wireErr != nil {
			s.observeBatchPreflight(in)
		}
	}()
	ids := make([]string, 0, len(in.Entries))
	total := 0
	for _, e := range in.Entries {
		ids = append(ids, value(e.Id))
		total += messageBodySize(value(e.MessageBody), e.MessageAttributes)
	}
	if err := validateBatch(ids); err != nil {
		return nil, err
	}
	if total > 1<<20 {
		return nil, failure("BatchRequestTooLong", "The combined size of all messages exceeds 1 MiB.")
	}
	if q.config.fifo {
		for _, entry := range in.Entries {
			if err := q.config.fifoParameters(value(entry.MessageGroupId), value(entry.MessageDeduplicationId), entry.DelaySeconds); err != nil {
				// AWS rejects the entire FIFO batch and models missing group
				// as InvalidParameterValue, unlike the single-send operation.
				if err.Code == "MissingParameter" {
					err.Code = "InvalidParameterValue"
				}
				return nil, err
			}
		}
	}
	out := &api.SendMessageBatchOutput{Successful: api.SendMessageBatchResultEntryList{}, Failed: api.BatchResultErrorEntryList{}}
	for _, e := range in.Entries {
		result, err := s.enqueue(r.Context(), q, &api.SendMessageInput{QueueUrl: in.QueueUrl, MessageBody: e.MessageBody, DelaySeconds: e.DelaySeconds, MessageAttributes: e.MessageAttributes, MessageSystemAttributes: e.MessageSystemAttributes, MessageGroupId: e.MessageGroupId, MessageDeduplicationId: e.MessageDeduplicationId})
		if err != nil {
			out.Failed = append(out.Failed, batchError(e.Id, err))
			continue
		}
		out.Successful = append(out.Successful, api.SendMessageBatchResultEntry{Id: e.Id, MessageId: result.MessageId, MD5OfMessageBody: result.MD5OfMessageBody, MD5OfMessageAttributes: result.MD5OfMessageAttributes, MD5OfMessageSystemAttributes: result.MD5OfMessageSystemAttributes, SequenceNumber: result.SequenceNumber})
	}
	return out, nil
}
func (s *Service) deleteBatch(r *http.Request, in *api.DeleteMessageBatchInput) (*api.DeleteMessageBatchOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	return s.deleteBatchEntries(q, in)
}

func (s *Service) deleteBatchEntries(q *queue, in *api.DeleteMessageBatchInput) (*api.DeleteMessageBatchOutput, *awswire.Error) {
	ids := make([]string, 0, len(in.Entries))
	for _, e := range in.Entries {
		ids = append(ids, value(e.Id))
	}
	if err := validateBatch(ids); err != nil {
		return nil, err
	}
	out := &api.DeleteMessageBatchOutput{Successful: api.DeleteMessageBatchResultEntryList{}, Failed: api.BatchResultErrorEntryList{}}
	for _, e := range in.Entries {
		if err := s.deleteReceipt(q, value(e.ReceiptHandle)); err != nil {
			out.Failed = append(out.Failed, batchError(e.Id, err))
		} else {
			out.Successful = append(out.Successful, api.DeleteMessageBatchResultEntry{Id: e.Id})
		}
	}
	return out, nil
}
func (s *Service) visibilityBatch(r *http.Request, in *api.ChangeMessageVisibilityBatchInput) (*api.ChangeMessageVisibilityBatchOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(in.Entries))
	for _, e := range in.Entries {
		ids = append(ids, value(e.Id))
	}
	if err := validateBatch(ids); err != nil {
		return nil, err
	}
	out := &api.ChangeMessageVisibilityBatchOutput{Successful: api.ChangeMessageVisibilityBatchResultEntryList{}, Failed: api.BatchResultErrorEntryList{}}
	for _, e := range in.Entries {
		if err := s.changeReceipt(q, value(e.ReceiptHandle), int(*e.VisibilityTimeout)); err != nil {
			out.Failed = append(out.Failed, batchError(e.Id, err))
		} else {
			out.Successful = append(out.Successful, api.ChangeMessageVisibilityBatchResultEntry{Id: e.Id})
		}
	}
	return out, nil
}
