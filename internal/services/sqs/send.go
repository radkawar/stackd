package sqs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/messageattribute"
	"stackd/journal"
)

func (s *Service) registerMessages() {
	register(s, "SendMessage", true, s.sendMessage)
	register(s, "ReceiveMessage", false, s.receiveMessage)
	register(s, "DeleteMessage", true, s.deleteMessage)
	register(s, "ChangeMessageVisibility", true, s.changeVisibility)
}
func (s *Service) sendMessage(r *http.Request, in *api.SendMessageInput) (*api.SendMessageOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	return s.enqueue(r.Context(), q, in)
}
func (s *Service) enqueue(ctx context.Context, q *queue, in *api.SendMessageInput) (*api.SendMessageOutput, *awswire.Error) {
	body := value(in.MessageBody)
	if len(body) == 0 {
		return nil, failure("InvalidParameterValue", "The message body must not be empty.")
	}
	if !validText(body) {
		return nil, failure("InvalidMessageContents", "Message body contains invalid characters.")
	}
	attrs, size, err := normalizeAttributes(in.MessageAttributes)
	if err != nil {
		return nil, err
	}
	if len(body)+size > q.config.maximumSize {
		return nil, failure("InvalidParameterValue", "Message exceeds the maximum allowed message size.")
	}
	trace, systemMD5, err := normalizeSystemAttributes(in.MessageSystemAttributes)
	if err != nil {
		return nil, err
	}
	if trace == "" {
		// An explicit system attribute takes precedence over transport tracing.
		// The HTTP header is not a submitted attribute and has no attribute MD5.
		if header := awsctx.FromContext(ctx).TraceHeader; tracePattern.MatchString(header) {
			trace = header
		}
	}
	delay := q.config.delay
	if in.DelaySeconds != nil {
		delay = int(*in.DelaySeconds)
		if delay < 0 || delay > 900 {
			return nil, failure("InvalidParameterValue", "Invalid per-message DelaySeconds.")
		}
	}
	group, dedup := value(in.MessageGroupId), value(in.MessageDeduplicationId)
	if in.MessageGroupId != nil && !messageattribute.ValidMessageID(group) {
		return nil, failure("InvalidParameterValue", "Invalid MessageGroupId.")
	}
	if in.MessageDeduplicationId != nil && !messageattribute.ValidMessageID(dedup) {
		return nil, failure("InvalidParameterValue", "Invalid MessageDeduplicationId.")
	}
	if q.config.fifo {
		if err := q.config.fifoParameters(group, dedup, in.DelaySeconds); err != nil {
			return nil, err
		}
		if dedup == "" {
			digest := sha256.Sum256([]byte(body))
			dedup = hex.EncodeToString(digest[:])
		}
	} else if in.MessageDeduplicationId != nil {
		return nil, failure("InvalidParameterValue", "MessageDeduplicationId is only valid for FIFO queues.")
	}
	out := &api.SendMessageOutput{MD5OfMessageBody: str(bodyDigest(body))}
	if len(attrs) > 0 {
		// Native SendMessage hashes the submitted spelling; ReceiveMessage
		// hashes the normalized stored attributes selected by that request.
		out.MD5OfMessageAttributes = str(attributeDigest(in.MessageAttributes))
	}
	if systemMD5 != "" {
		out.MD5OfMessageSystemAttributes = str(systemMD5)
	}
	now := s.now()
	s.prune(q, now)
	if q.config.fifo {
		if previous, ok := q.dedup[q.dedupKey(group, dedup)]; ok {
			out.MessageId = str(previous.id)
			out.SequenceNumber = str(previous.sequence)
			s.observeSend(in, true)
			return out, s.recordSend(ctx, q, previous.id)
		}
	}
	encoded, encodeErr := s.seal(ctx, q, payload{Body: body, Attributes: attrs, Trace: trace})
	if encodeErr != nil {
		return nil, encodeErr
	}
	scope := awsctx.FromContext(ctx)
	sender := scope.PrincipalID
	if sender == "" {
		sender = scope.AccountID
	}
	s.observeSend(in, false)
	m := &message{id: identifier(), group: group, dedup: dedup, sender: sender, data: encoded.data, encrypted: encoded.encrypted, keyARN: encoded.keyARN, dataKey: encoded.dataKey, bodyMD5: value(out.MD5OfMessageBody), sent: now, retentionStarted: now, available: now.Add(time.Duration(delay) * time.Second)}
	out.MessageId = str(m.id)
	q.appendMessage(m, now)
	if q.config.fifo {
		out.SequenceNumber = str(m.sequence)
	}
	return out, s.recordSend(ctx, q, m.id)
}

func (c queueConfig) fifoParameters(group, dedup string, delay *api.NullableInteger) *awswire.Error {
	if delay != nil && *delay != 0 {
		return failure("InvalidParameterValue", "FIFO queues do not support per-message delay.")
	}
	if group == "" {
		return failure("MissingParameter", "MessageGroupId is required for FIFO queues.")
	}
	if dedup == "" && !c.contentDedup {
		return failure("InvalidParameterValue", "MessageDeduplicationId is required unless content-based deduplication is enabled.")
	}
	return nil
}

func (s *Service) recordSend(ctx context.Context, q *queue, messageID string) *awswire.Error {
	if s.journal == nil {
		return nil
	}
	err := s.journal.AppendSQSMessageAccepted(ctx, apievents.WithOrigin(ctx, journal.Envelope{At: s.now(),
		Partition: q.key.partition, AccountID: q.key.account, Region: q.key.region}),
		journal.SQSMessageAccepted{MessageID: messageID, QueueARN: q.key.arn()})
	if err != nil {
		// A journal failure aborts the entire command, including batch sends.
		s.stateErr = err
		return storageError(err)
	}
	return nil
}
