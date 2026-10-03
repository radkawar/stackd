package sqs

import (
	"context"
	"errors"

	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
)

// CheckSendToQueue evaluates current destination state and policies without a
// synthetic message or the queue runtime lock. It can join a source transaction.
func (s *Service) CheckSendToQueue(ctx context.Context, arn string) *awswire.Error {
	_, _, err := s.checkQueuePermissions(ctx, arn, "SendMessage")
	return err
}

// CheckConsumeQueue reads current source configuration and checks all queue
// permissions needed by a consumer. It does not receive messages, prepare KMS
// keys or record a synthetic GetQueueAttributes API call. A failed permission
// identifies its action so the consumer can project its own service error.
func (s *Service) CheckConsumeQueue(ctx context.Context, arn string) (QueueConfiguration, string, *awswire.Error) {
	return s.checkQueuePermissions(ctx, arn, "ReceiveMessage", "DeleteMessage", "GetQueueAttributes")
}

func (s *Service) checkQueuePermissions(ctx context.Context, arn string, actions ...string) (QueueConfiguration, string, *awswire.Error) {
	key, valid := parseQueueARN(arn)
	if !valid {
		return QueueConfiguration{}, "", failure("InvalidAddress", "A complete SQS queue ARN is required.")
	}
	var configuration QueueConfiguration
	var failedAction string
	err := s.repository.View(ctx, func(r Reader) error {
		record, err := r.Queue(publicKey(key))
		if errors.Is(err, ErrNotFound) {
			return failure("QueueDoesNotExist", "The specified queue does not exist.")
		}
		if err != nil {
			return err
		}
		values := make(map[string][]string, len(record.Tags))
		for _, tag := range record.Tags {
			values["aws:ResourceTag/"+tag.Key] = []string{tag.Value}
		}
		now := s.clock.Now()
		permission := authorization.Request{
			ResourceARN: arn, Context: values, EvaluationTime: &now,
			ResourcePolicies: []authorization.BoundPolicy{{Document: record.Configuration.Policy, PrincipalIDs: record.Configuration.PolicyPrincipals}},
		}
		for _, action := range actions {
			permission.Action = "sqs:" + action
			if wire := s.authorizer.Authorize(r.Context(), permission); wire != nil {
				failedAction = action
				return wire
			}
		}
		configuration = record.Configuration
		return nil
	})
	if err != nil {
		return QueueConfiguration{}, failedAction, storageError(err)
	}
	return configuration, "", nil
}

// SendToQueue uses the normal SQS command and current permissions for an internal
// delivery addressed by ARN. The ARN replaces the transport-only QueueUrl field;
// all message fields retain their SendMessage semantics.
func (s *Service) SendToQueue(ctx context.Context, arn string, in *api.SendMessageInput) (result *api.SendMessageOutput, wireErr *awswire.Error) {
	audit := &commandAudit{action: "SendMessage", input: in, final: true, resourceARN: arn}
	defer s.completeCommand(ctx, audit, &wireErr)
	key, valid := parseQueueARN(arn)
	if !valid {
		return nil, failure("InvalidAddress", "A complete SQS queue ARN is required.")
	}
	// Internal deliveries have no HTTP endpoint. Give the actual generated
	// command its canonical queue URL without mutating the caller's input.
	command := *in
	command.QueueUrl = str(key.canonicalURL())
	in = &command
	audit.input = in
	var q *queue
	var output *api.SendMessageOutput
	err := s.authorizedCommand(ctx, audit, func(context.Context) ([]authorization.Request, *awswire.Error) {
		var err *awswire.Error
		q, err = s.queueByKey(key)
		if err != nil {
			return nil, err
		}
		return []authorization.Request{queuePermission(q, "SendMessage")}, nil
	}, func(ctx context.Context) *awswire.Error {
		var err *awswire.Error
		output, err = s.enqueue(ctx, q, in)
		audit.output = output
		return err
	})
	if err != nil {
		return nil, err
	}
	return output, nil
}

// ReceiveFromQueue uses normal receive validation, authorization, decryption and
// long polling with an ARN in place of the transport-only QueueUrl. The caller's
// generated input is not modified.
func (s *Service) ReceiveFromQueue(ctx context.Context, arn string, in *api.ReceiveMessageInput) (result *api.ReceiveMessageOutput, wireErr *awswire.Error) {
	audit := &commandAudit{action: "ReceiveMessage", input: in, resourceARN: arn}
	defer s.completeCommand(ctx, audit, &wireErr)
	key, valid := parseQueueARN(arn)
	if !valid {
		return nil, failure("InvalidAddress", "A complete SQS queue ARN is required.")
	}
	command := *in
	command.QueueUrl = str(key.canonicalURL())
	audit.input = &command
	return s.receive(ctx, &command, audit, func() (*queue, *awswire.Error) {
		return s.queueByKey(key)
	})
}

// DeleteFromQueue applies DeleteMessageBatch to an ARN-addressed queue with the
// caller's current permissions. Every entry retains ordinary receipt semantics,
// and successful deletions and the API outcome commit in one transaction.
func (s *Service) DeleteFromQueue(ctx context.Context, arn string, in *api.DeleteMessageBatchInput) (result *api.DeleteMessageBatchOutput, wireErr *awswire.Error) {
	audit := &commandAudit{action: "DeleteMessageBatch", input: in, final: true, resourceARN: arn}
	defer s.completeCommand(ctx, audit, &wireErr)
	key, valid := parseQueueARN(arn)
	if !valid {
		return nil, failure("InvalidAddress", "A complete SQS queue ARN is required.")
	}
	command := *in
	command.QueueUrl = str(key.canonicalURL())
	audit.input = &command
	var q *queue
	var output *api.DeleteMessageBatchOutput
	err := s.authorizedCommand(ctx, audit, func(context.Context) ([]authorization.Request, *awswire.Error) {
		var err *awswire.Error
		q, err = s.queueByKey(key)
		if err != nil {
			return nil, err
		}
		return []authorization.Request{queuePermission(q, "DeleteMessage")}, nil
	}, func(context.Context) *awswire.Error {
		var err *awswire.Error
		output, err = s.deleteBatchEntries(q, &command)
		audit.output = output
		return err
	})
	if err != nil {
		return nil, err
	}
	return output, nil
}

// Failed commands have already rolled back their attempted resource changes.
// Record the rejection in the caller's live transaction when present, retaining
// the outcome even when cancellation ended a long poll.
func (s *Service) completeCommand(ctx context.Context, audit *commandAudit, wireErr **awswire.Error) {
	if *wireErr == nil || (s.apiEvents == nil && s.metrics == nil) {
		return
	}
	ctx, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	if err := s.recordAPI(ctx, audit, *wireErr, s.clock.Now()); err != nil {
		*wireErr = storageError(err)
	}
}
