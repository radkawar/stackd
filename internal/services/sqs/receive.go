package sqs

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
	"stackd/internal/messageattribute"
)

func (s *Service) receiveMessage(r *http.Request, in *api.ReceiveMessageInput) (*api.ReceiveMessageOutput, *awswire.Error) {
	audit := &commandAudit{action: "ReceiveMessage", input: in}
	return s.receive(r.Context(), in, audit, func() (*queue, *awswire.Error) {
		return s.queueFor(r, value(in.QueueUrl))
	})
}

// receive owns long polling for both URL and ARN callers. Resolution and
// authorization run again in every transaction, including data-key retries.
func (s *Service) receive(ctx context.Context, in *api.ReceiveMessageInput, audit *commandAudit, resolve func() (*queue, *awswire.Error)) (*api.ReceiveMessageOutput, *awswire.Error) {
	max := 1
	if in.MaxNumberOfMessages != nil {
		max = int(*in.MaxNumberOfMessages)
	}
	if max < 1 || max > 10 {
		return nil, failure("InvalidParameterValue", "MaxNumberOfMessages must be between 1 and 10.")
	}
	if in.VisibilityTimeout != nil && (*in.VisibilityTimeout < 0 || *in.VisibilityTimeout > 43200) {
		return nil, failure("InvalidParameterValue", "VisibilityTimeout must be between 0 and 43200.")
	}
	if in.WaitTimeSeconds != nil && (*in.WaitTimeSeconds < 0 || *in.WaitTimeSeconds > 20) {
		return nil, failure("InvalidParameterValue", "WaitTimeSeconds must be between 0 and 20.")
	}
	// Registration and Close share mu so shutdown cannot miss a new long poll.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, &awswire.Error{Code: "ServiceUnavailable", Message: "The SQS service is shutting down.", StatusCode: 503}
	}
	s.polls.Add(1)
	s.mu.Unlock()
	defer s.polls.Done()

	var originalID string
	var deadline time.Time
	for {
		var out *api.ReceiveMessageOutput
		var changed <-chan struct{}
		var next time.Time
		var done bool
		var q *queue
		err := s.authorizedCommand(ctx, audit, func(context.Context) ([]authorization.Request, *awswire.Error) {
			var err *awswire.Error
			q, err = resolve()
			if err != nil {
				return nil, err
			}
			return []authorization.Request{queuePermission(q, "ReceiveMessage")}, nil
		}, func(ctx context.Context) *awswire.Error {
			wait := q.config.wait
			if in.WaitTimeSeconds != nil {
				wait = int(*in.WaitTimeSeconds)
			}
			if originalID == "" {
				originalID = q.id
				deadline = s.now().Add(time.Duration(wait) * time.Second)
			}
			if q.id != originalID {
				return failure("QueueDoesNotExist", "The queue was deleted while receiving messages.")
			}
			var err *awswire.Error
			out, err = s.receiveAvailable(ctx, q, in, max)
			if err != nil {
				return err
			}
			done = len(out.Messages) > 0 || wait == 0 || !s.now().Before(deadline)
			audit.final, audit.output = done, out
			changed = q.changed
			next = s.nextWake(q, deadline)
			return nil
		})
		if err != nil {
			return nil, err
		}
		if done {
			return out, nil
		}
		// Absolute registration remains correct if time advanced after the
		// transaction selected its next deadline. An already-due timer fires now.
		timer := s.clock.NewTimerAt(next)
		select {
		case <-s.lifetime.Done():
			timer.Stop()
			return nil, &awswire.Error{Code: "ServiceUnavailable", Message: "The SQS service is shutting down.", StatusCode: 503}
		case <-ctx.Done():
			timer.Stop()
			return nil, &awswire.Error{Code: "RequestCanceled", Message: "The receive request was canceled.", StatusCode: 408}
		case <-changed:
			timer.Stop()
		case <-timer.C():
		}
	}
}

func (s *Service) nextWake(q *queue, deadline time.Time) time.Time {
	next := deadline
	now := s.now()
	for _, m := range q.messages {
		for _, at := range []time.Time{m.available, m.retentionStarted.Add(time.Duration(q.config.retention) * time.Second)} {
			if at.After(now) && at.Before(next) {
				next = at
			}
		}
	}
	return next
}
func (s *Service) receiveAvailable(ctx context.Context, q *queue, in *api.ReceiveMessageInput, max int) (*api.ReceiveMessageOutput, *awswire.Error) {
	now := s.now()
	visibility := q.config.visibility
	if in.VisibilityTimeout != nil {
		visibility = int(*in.VisibilityTimeout)
	}
	attemptID := value(in.ReceiveRequestAttemptId)
	if in.ReceiveRequestAttemptId != nil && (!q.config.fifo || !messageattribute.ValidMessageID(attemptID)) {
		return nil, failure("InvalidParameterValue", "ReceiveRequestAttemptId requires a FIFO queue and a valid token.")
	}
	if attempt, ok := q.attempts[attemptID]; ok {
		for i, m := range attempt.messages {
			if !q.contains(m) || m.generation != attempt.generations[i] || m.receipt != attempt.handles[i] {
				return nil, failure("InvalidParameterValue", "The receive attempt contains messages modified since the original request.")
			}
		}
		out := &api.ReceiveMessageOutput{}
		for _, m := range attempt.messages {
			data, err := s.receiveOutput(ctx, q, m, in)
			if err != nil {
				return nil, err
			}
			m.available = now.Add(time.Duration(visibility) * time.Second)
			m.lastReceived = now
			out.Messages = append(out.Messages, data)
		}
		return out, nil
	}
	inflight, groups := q.updateFairness(now)
	if inflight >= 120000 {
		if q.config.fifo || in.WaitTimeSeconds != nil && *in.WaitTimeSeconds > 0 || in.WaitTimeSeconds == nil && q.config.wait > 0 {
			return &api.ReceiveMessageOutput{}, nil
		}
		return nil, failure("OverLimit", "The queue has reached its in-flight message limit.")
	}
	candidates := q.availableMessages(now)
	q.prioritizeMessages(candidates, groups)
	var selected []*message
	for _, m := range candidates {
		if len(selected) == max {
			break
		}
		if q.config.redrive != nil && m.receives >= q.config.redrive.MaxReceiveCount {
			moved, err := s.toDeadLetter(ctx, q, m, now)
			if err != nil {
				return nil, err
			}
			if moved {
				continue
			}
		}
		// Decode before changing receipt/visibility state. Corrupted encrypted data
		// must not make a message disappear from subsequent receive attempts.
		if _, err := s.open(ctx, q, m); err != nil {
			return nil, err
		}
		selected = append(selected, m)
	}
	out := &api.ReceiveMessageOutput{}
	attempt := receiveAttempt{expires: now.Add(5 * time.Minute)}
	for _, m := range selected {
		m.receives++
		m.queueReceives++
		m.generation++
		m.lastReceived = now
		if m.firstReceived.IsZero() {
			m.firstReceived = now
		}
		m.receipt = identifier() + identifier()
		m.available = now.Add(time.Duration(visibility) * time.Second)
		q.receipts[m.receipt] = receipt{message: m, expires: now.Add(time.Duration(q.config.retention) * time.Second)}
		data, err := s.receiveOutput(ctx, q, m, in)
		if err != nil {
			return nil, err
		}
		out.Messages = append(out.Messages, data)
		attempt.messages = append(attempt.messages, m)
		attempt.handles = append(attempt.handles, m.receipt)
		attempt.generations = append(attempt.generations, m.generation)
	}
	if attemptID != "" && len(selected) > 0 {
		q.attempts[attemptID] = attempt
	}
	return out, nil
}
func (s *Service) receiveOutput(ctx context.Context, q *queue, m *message, in *api.ReceiveMessageInput) (api.Message, *awswire.Error) {
	p, err := s.open(ctx, q, m)
	if err != nil {
		return api.Message{}, err
	}
	out := api.Message{MessageId: str(m.id), ReceiptHandle: str(m.receipt), Body: str(p.Body), MD5OfBody: str(m.bodyMD5)}
	for name, a := range p.Attributes {
		for _, requested := range in.MessageAttributeNames {
			n := string(requested)
			if n == "All" || n == ".*" || n == string(name) || strings.HasSuffix(n, ".*") && strings.HasPrefix(string(name), strings.TrimSuffix(n, "*")) {
				if out.MessageAttributes == nil {
					out.MessageAttributes = make(api.MessageBodyAttributeMap)
				}
				out.MessageAttributes[name] = a
				break
			}
		}
	}
	if len(out.MessageAttributes) > 0 {
		out.MD5OfMessageAttributes = str(attributeDigest(out.MessageAttributes))
	}
	system := api.MessageSystemAttributeMap{"SenderId": api.String(m.sender), "SentTimestamp": api.String(strconv.FormatInt(m.sent.UnixMilli(), 10)), "ApproximateReceiveCount": api.String(strconv.Itoa(m.receives)), "ApproximateFirstReceiveTimestamp": api.String(strconv.FormatInt(m.firstReceived.UnixMilli(), 10))}
	if m.group != "" {
		system["MessageGroupId"] = api.String(m.group)
	}
	if q.config.fifo {
		system["MessageDeduplicationId"] = api.String(m.dedup)
		system["SequenceNumber"] = api.String(m.sequence)
	}
	if p.Trace != "" {
		system["AWSTraceHeader"] = api.String(p.Trace)
	}
	if m.sourceARN != "" {
		system["DeadLetterQueueSourceArn"] = api.String(m.sourceARN)
	}
	requested := make([]string, 0, len(in.AttributeNames)+len(in.MessageSystemAttributeNames))
	for _, n := range in.AttributeNames {
		requested = append(requested, string(n))
	}
	for _, n := range in.MessageSystemAttributeNames {
		requested = append(requested, string(n))
	}
	for _, name := range requested {
		if name == "All" {
			out.Attributes = system
			break
		}
		if v, ok := system[api.MessageSystemAttributeName(name)]; ok {
			if out.Attributes == nil {
				out.Attributes = make(api.MessageSystemAttributeMap)
			}
			out.Attributes[api.MessageSystemAttributeName(name)] = v
		}
	}
	return out, nil
}
func (s *Service) toDeadLetter(ctx context.Context, source *queue, m *message, now time.Time) (bool, *awswire.Error) {
	key, _ := parseQueueARN(source.config.redrive.DeadLetterTargetARN)
	target := s.lookupQueue(key)
	if target == nil {
		return false, nil
	}
	s.loadMessages(target)
	s.prune(target, now)
	if target.config.fifo {
		if _, duplicate := target.dedup[target.dedupKey(m.group, m.id)]; duplicate {
			source.remove(m)
			return true, nil
		}
	}
	p, err := s.open(ctx, source, m)
	if err != nil {
		return false, err
	}
	data, err := s.seal(ctx, target, p)
	if err != nil {
		return false, err
	}
	source.remove(m)
	moved := *m
	moved.data = data.data
	moved.encrypted = data.encrypted
	moved.keyARN = data.keyARN
	moved.dataKey = data.dataKey
	moved.receipt = ""
	moved.lastReceived = time.Time{}
	moved.available = now
	moved.sourceARN = source.key.arn()
	if target.config.fifo {
		moved.retentionStarted = now
		moved.dedup = m.id
	}
	target.appendMessage(&moved, now)
	return true, nil
}
