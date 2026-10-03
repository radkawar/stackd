package lambda

import (
	"context"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
)

// SQSSource opens a queue consumer under the function's execution role. Polling
// is a Lambda service action, not customer code: its role session must not carry
// the lambda:SourceFunctionArn context supplied to calls from a runtime.
// Sessions and queue effects are external to Lambda repository transactions.
type SQSSource interface {
	Open(ctx context.Context, function FunctionKey, roleARN, sourceARN string) (SQSConsumer, *awswire.Error)
}

// SQSQueueInfo contains the typed queue settings required by mapping admission.
// Queue state and permissions remain authoritative in SQS.
type SQSQueueInfo struct {
	VisibilitySeconds int
	FIFO              bool
}

// SQSConsumer is bound to one queue ARN and execution role. Each command uses
// current queue permissions; the implementation owns credential renewal.
// QueueUrl is transport-only and is supplied by the bound queue, not the caller.
// Successful Receive and Delete commands return a non-nil generated output.
type SQSConsumer interface {
	Check(context.Context) (SQSQueueInfo, *awswire.Error)
	Receive(context.Context, *api.ReceiveMessageInput) (*api.ReceiveMessageOutput, *awswire.Error)
	Delete(context.Context, *api.DeleteMessageBatchInput) (*api.DeleteMessageBatchOutput, *awswire.Error)
}
