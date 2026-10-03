package integrations

import (
	"context"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
	"stackd/internal/services/lambda"
	"stackd/internal/services/sqs"
)

// LambdaSQSQueues keeps source state, permissions and receipts in the SQS owner.
type LambdaSQSQueues interface {
	CheckConsumeQueue(context.Context, string) (sqs.QueueConfiguration, string, *awswire.Error)
	ReceiveFromQueue(context.Context, string, *api.ReceiveMessageInput) (*api.ReceiveMessageOutput, *awswire.Error)
	DeleteFromQueue(context.Context, string, *api.DeleteMessageBatchInput) (*api.DeleteMessageBatchOutput, *awswire.Error)
}

// LambdaSQS supplies execution-role consumers to Lambda's event-source workers.
// Runtime credentials and poller credentials have different IAM context: only
// the former carry lambda:SourceFunctionArn.
type LambdaSQS struct {
	Roles  ServiceRoles
	Queues LambdaSQSQueues
}

func (a LambdaSQS) Open(ctx context.Context, function lambda.FunctionKey, roleARN, sourceARN string) (lambda.SQSConsumer, *awswire.Error) {
	session, wire := openLambdaSourceSession(ctx, a.Roles, function, roleARN)
	if wire != nil {
		return nil, wire
	}
	return &lambdaSQSConsumer{provider: a, session: session, sourceARN: sourceARN}, nil
}

type lambdaSQSConsumer struct {
	provider  LambdaSQS
	session   *lambdaSourceSession
	sourceARN string
}

func (c *lambdaSQSConsumer) Check(ctx context.Context) (lambda.SQSQueueInfo, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return lambda.SQSQueueInfo{}, wire
	}
	configuration, action, wire := c.provider.Queues.CheckConsumeQueue(ctx, c.sourceARN)
	if wire != nil {
		if action != "" && wire.StatusCode < 500 {
			return lambda.SQSQueueInfo{}, &awswire.Error{Code: "InvalidParameterValueException", Message: "The function execution role does not have permissions to call " + action + " on SQS", StatusCode: 400}
		}
		return lambda.SQSQueueInfo{}, wire
	}
	return lambda.SQSQueueInfo{VisibilitySeconds: configuration.VisibilitySeconds, FIFO: configuration.FIFO}, nil
}

func (c *lambdaSQSConsumer) Receive(ctx context.Context, input *api.ReceiveMessageInput) (*api.ReceiveMessageOutput, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	return c.provider.Queues.ReceiveFromQueue(ctx, c.sourceARN, input)
}

func (c *lambdaSQSConsumer) Delete(ctx context.Context, input *api.DeleteMessageBatchInput) (*api.DeleteMessageBatchOutput, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	return c.provider.Queues.DeleteFromQueue(ctx, c.sourceARN, input)
}
