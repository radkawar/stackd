package journal

import (
	"context"
	"stackd/journal"
	"stackd/storage/sqlite/journal/internal/sqlcgen"
)

const eventBridgeAcceptedType = "eventbridge.accepted.v1"

func (s *storage) AppendEventBridgeAccepted(ctx context.Context, e journal.Envelope, event journal.EventBridgeAccepted) error {
	return s.append(ctx, e, eventBridgeAcceptedType, func(ctx context.Context, q *sqlcgen.Queries, sequence int64) error {
		return q.AppendEventBridgeAccepted(ctx, sqlcgen.AppendEventBridgeAcceptedParams{Sequence: sequence, EventID: event.EventID, WireEventID: event.WireEventID, EventBusArn: event.EventBusARN})
	})
}

const sqsMessageAcceptedType = "sqs.message.accepted.v1"

func (s *storage) AppendSQSMessageAccepted(ctx context.Context, e journal.Envelope, event journal.SQSMessageAccepted) error {
	return s.append(ctx, e, sqsMessageAcceptedType, func(ctx context.Context, q *sqlcgen.Queries, sequence int64) error {
		return q.AppendSQSMessageAccepted(ctx, sqlcgen.AppendSQSMessageAcceptedParams{Sequence: sequence, MessageID: event.MessageID, QueueArn: event.QueueARN})
	})
}

const lambdaInvocationAcceptedType = "lambda.invocation.accepted.v1"

func (s *storage) AppendLambdaInvocationAccepted(ctx context.Context, e journal.Envelope, event journal.LambdaInvocationAccepted) error {
	return s.append(ctx, e, lambdaInvocationAcceptedType, func(ctx context.Context, q *sqlcgen.Queries, sequence int64) error {
		return q.AppendLambdaInvocationAccepted(ctx, sqlcgen.AppendLambdaInvocationAcceptedParams{Sequence: sequence, InvocationID: event.InvocationID, FunctionArn: event.FunctionARN})
	})
}

const lambdaSourceBatchAcceptedType = "lambda.source_batch.accepted.v1"

func (s *storage) AppendLambdaSourceBatchAccepted(ctx context.Context, e journal.Envelope, event journal.LambdaSourceBatchAccepted) error {
	return s.append(ctx, e, lambdaSourceBatchAcceptedType, func(ctx context.Context, q *sqlcgen.Queries, sequence int64) error {
		if err := q.AppendLambdaSourceBatchAccepted(ctx, sqlcgen.AppendLambdaSourceBatchAcceptedParams{Sequence: sequence, InvocationEventID: event.InvocationEventID, MappingArn: event.MappingARN, SourceArn: event.SourceARN}); err != nil {
			return err
		}
		for i, id := range event.RecordIDs {
			if err := q.AppendLambdaSourceBatchRecord(ctx, sqlcgen.AppendLambdaSourceBatchRecordParams{Sequence: sequence, Ordinal: int64(i), RecordID: id}); err != nil {
				return err
			}
		}
		return nil
	})
}

const logsBatchAcceptedType = "logs.batch.accepted.v1"

func (s *storage) AppendLogsBatchAccepted(ctx context.Context, e journal.Envelope, event journal.LogsBatchAccepted) error {
	return s.append(ctx, e, logsBatchAcceptedType, func(ctx context.Context, q *sqlcgen.Queries, sequence int64) error {
		return q.AppendLogsBatchAccepted(ctx, sqlcgen.AppendLogsBatchAcceptedParams{Sequence: sequence, BatchID: event.BatchID, LogGroupArn: event.LogGroupARN, LogStreamName: event.LogStreamName, EventCount: event.EventCount})
	})
}
