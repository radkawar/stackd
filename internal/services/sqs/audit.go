package sqs

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// commandAudit belongs to a single API command, not an encryption attempt or
// receive poll. Only the final successful repository callback records it.
type commandAudit struct {
	action           string
	input            any
	output           any
	final            bool
	resourceARN      string
	sendSizes        []int64
	deduplicated     int64
	failedBatchSizes bool
}

var sqsAuditRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"MessageBody":               {Mode: awsapi.RedactField},
	"MessageAttributes":         {Mode: awsapi.RedactField},
	"Entries.MessageBody":       {Mode: awsapi.RedactField},
	"Entries.MessageAttributes": {Mode: awsapi.RedactField},
	"MessageAttributeNames":     {Mode: awsapi.RedactField},
}}

func sqsProjection(action string) apievents.Projection {
	p := apievents.Projection{Category: journal.CategoryManagement, Request: sqsAuditRequest}
	// AWS's SQS CloudTrail operation table explicitly classifies queue reads as
	// data events. ReceiveMessage is readOnly despite changing delivery state.
	switch action {
	case "ChangeMessageVisibility", "ChangeMessageVisibilityBatch", "DeleteMessage", "DeleteMessageBatch", "GetQueueAttributes", "GetQueueUrl", "ListDeadLetterSourceQueues", "ListQueues", "ListQueueTags", "ReceiveMessage", "SendMessage", "SendMessageBatch":
		p.Category = journal.CategoryData
	}
	switch action {
	case "GetQueueAttributes", "GetQueueUrl", "ListDeadLetterSourceQueues", "ListQueues", "ListQueueTags", "ReceiveMessage", "ListMessageMoveTasks":
		p.ReadOnly = true
	}
	switch action {
	case "CreateQueue", "SendMessage", "SendMessageBatch", "DeleteMessageBatch", "ChangeMessageVisibilityBatch", "StartMessageMoveTask", "CancelMessageMoveTask":
		p.Response = &awsapi.DocumentProjection{}
	}
	return p
}

func sqsBatchResponse(successful, failed int) *awsapi.DocumentProjection {
	p := &awsapi.DocumentProjection{}
	if successful == 0 || failed == 0 {
		p.Fields = make(map[string]awsapi.FieldProjection, 2)
		if successful == 0 {
			p.Fields["Successful"] = awsapi.FieldProjection{Mode: awsapi.OmitField}
		}
		if failed == 0 {
			p.Fields["Failed"] = awsapi.FieldProjection{Mode: awsapi.OmitField}
		}
	}
	return p
}

func (s *Service) recordAPI(ctx context.Context, audit *commandAudit, failure *awswire.Error, at time.Time) error {
	if s.apiEvents == nil && (failure == nil || s.metrics == nil) {
		return nil
	}
	model, _ := awscatalog.LookupService("sqs")
	op, known := model.Operation(audit.action)
	if !known {
		return nil
	}
	input := audit.input
	if in, ok := input.(*api.ListDeadLetterSourceQueuesInput); ok && in != nil && in.MaxResults == nil {
		// Observed even when omitted by the caller; this is not a general
		// default-insertion rule for other list operations.
		native := *in
		native.MaxResults = ptr(api.BoxedInteger(0))
		input = &native
	}
	projection := sqsProjection(audit.action)
	// Native batch events omit empty result lists, unlike the HTTP response.
	// Keep the generated DTO unchanged for SDK callers and message semantics.
	switch out := audit.output.(type) {
	case *api.SendMessageBatchOutput:
		if out != nil {
			projection.Response = sqsBatchResponse(len(out.Successful), len(out.Failed))
		}
	case *api.DeleteMessageBatchOutput:
		if out != nil {
			projection.Response = sqsBatchResponse(len(out.Successful), len(out.Failed))
		}
	case *api.ChangeMessageVisibilityBatchOutput:
		if out != nil {
			projection.Response = sqsBatchResponse(len(out.Successful), len(out.Failed))
		}
	}
	call, err := projection.Call(model, op, input, audit.output, failure)
	if err != nil {
		return err
	}
	m := awsctx.FromContext(ctx)
	scope := journal.Envelope{At: at, Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
	// Resource references come from the generated, already-redacted projection;
	// this does not maintain a second DTO encoder or inspect raw request bytes.
	var refs struct {
		QueueURL   string `json:"queueUrl"`
		QueueName  string `json:"queueName"`
		QueueOwner string `json:"queueOwnerAWSAccountId"`
		SourceARN  string `json:"sourceArn"`
	}
	if err := json.Unmarshal(call.RequestParameters, &refs); err != nil && len(call.RequestParameters) != 0 {
		return err
	}
	key := queueKey{partition: m.Partition, account: m.AccountID, region: m.Region, name: refs.QueueName}
	if refs.QueueOwner != "" {
		key.account = refs.QueueOwner
	}
	if audit.action == "ListQueues" {
		key.name = "*"
	}
	if refs.QueueURL != "" {
		if u, err := url.Parse(refs.QueueURL); err == nil {
			parts := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(parts) == 2 {
				key.account, key.name = parts[0], parts[1]
			}
		}
	}
	arn := audit.resourceARN
	if arn == "" {
		arn = refs.SourceARN
	}
	if parsed, ok := parseQueueARN(arn); ok {
		key = parsed
	}
	if key.name != "" {
		scope.Partition, scope.AccountID, scope.Region = key.partition, key.account, key.region
		call.EventResources = []journal.APIEventResource{{AccountID: key.account, Type: "AWS::SQS::Queue", ARN: key.arn()}}
		name := refs.QueueURL
		if name == "" {
			name = key.name
		}
		call.Resources = []journal.APIResource{{Type: "AWS::SQS::Queue", Name: name}}
	}
	record := func(ctx context.Context) error {
		if s.apiEvents == nil {
			return nil
		}
		return s.apiEvents.Record(ctx, scope, call)
	}
	if failure == nil || s.metrics == nil || key.name == "" || key.name == "*" {
		return record(ctx)
	}
	// An authenticated rejected access activates an existing queue too. Its
	// activity and any preflight batch-size observations commit with the failed
	// API outcome, never with a partially applied resource command.
	err = s.repository.Update(ctx, func(tx Transaction) error {
		queue, err := tx.Queue(publicKey(key))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil {
			activateQueueMetrics(&queue.MetricActiveUntil, &queue.NextMetricSample, at)
			if err := tx.PutQueue(queue); err != nil {
				return err
			}
			if audit.failedBatchSizes {
				publication := MetricPublicationKey{Queue: queue.Key, Minute: at.UTC().Truncate(time.Minute)}
				if err := tx.AddMetricSamples(publication, audit.messageSizeSamples()); err != nil {
					return err
				}
			}
		}
		return record(tx.Context())
	})
	if err == nil {
		s.jobs.Wake()
	}
	return err
}

// RecordRequestError observes authenticated known-operation failures before a
// service command can execute. Failed decoding never exposes the original body.
func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, failure *awswire.Error) error {
	action := string(request.Operation.Name)
	if _, implemented := s.operations[action]; !implemented {
		return nil
	}
	return s.recordAPI(ctx, &commandAudit{action: action, input: request.Input}, failure, s.clock.Now())
}
