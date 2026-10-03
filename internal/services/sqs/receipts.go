package sqs

import (
	"net/http"
	"time"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
)

func (s *Service) deleteMessage(r *http.Request, in *api.DeleteMessageInput) (*api.DeleteMessageOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	if err := s.deleteReceipt(q, value(in.ReceiptHandle)); err != nil {
		return nil, err
	}
	return &api.DeleteMessageOutput{}, nil
}
func (s *Service) deleteReceipt(q *queue, handle string) *awswire.Error {
	rec, ok := q.receipts[handle]
	if !ok {
		return failure("ReceiptHandleIsInvalid", "The input receipt handle is invalid.")
	}
	// Standard SQS accepts a stale handle without guaranteeing deletion. Only
	// the most recent receipt may remove this delivery's message.
	if rec.message.receipt != handle {
		return nil
	}
	if q.config.fifo && !s.now().Before(rec.message.available) {
		return failure("InvalidParameterValue", "The receipt handle has expired.")
	}
	q.remove(rec.message)
	return nil
}
func (s *Service) changeVisibility(r *http.Request, in *api.ChangeMessageVisibilityInput) (*api.ChangeMessageVisibilityOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	if err := s.changeReceipt(q, value(in.ReceiptHandle), int(*in.VisibilityTimeout)); err != nil {
		return nil, err
	}
	return &api.ChangeMessageVisibilityOutput{}, nil
}
func (s *Service) changeReceipt(q *queue, handle string, seconds int) *awswire.Error {
	if seconds < 0 || seconds > 43200 {
		return failure("InvalidParameterValue", "VisibilityTimeout must be between 0 and 43200.")
	}
	rec, ok := q.receipts[handle]
	if !ok || rec.message.receipt != handle {
		return failure("ReceiptHandleIsInvalid", "The input receipt handle is invalid.")
	}
	m := rec.message
	now := s.now()
	if !q.contains(m) || !now.Before(m.available) {
		return failure("MessageNotInflight", "The specified message is not in flight.")
	}
	available := now.Add(time.Duration(seconds) * time.Second)
	if available.After(m.lastReceived.Add(12 * time.Hour)) {
		return failure("InvalidParameterValue", "VisibilityTimeout exceeds the maximum remaining lifetime of this receipt.")
	}
	m.available = available
	m.generation++
	q.notify()
	return nil
}
