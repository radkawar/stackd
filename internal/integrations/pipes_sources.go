package integrations

import (
	"context"
	dynamodbapi "stackd/internal/awsapi/dynamodbstreams"
	kinesisapi "stackd/internal/awsapi/kinesis"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/lambda"
	"stackd/internal/services/pipes"
)

// PipesSources borrows source command contracts, never Lambda credentials,
// mappings, checkpoints, timers, or ownership.
type PipesSources struct {
	Roles           ServiceRoles
	Queues          LambdaSQSQueues
	KinesisStreams  LambdaKinesisStreams
	DynamoDBStreams LambdaDynamoDBStreams
}
type pipesSession struct {
	roles    ServiceRoles
	pipe     pipes.PipeRecord
	sessions serviceRoleSessions
}

func (s *pipesSession) context(ctx context.Context) (context.Context, *awswire.Error) {
	m := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition:     s.pipe.Key.Partition,
		AccountID:     s.pipe.Key.AccountID,
		Region:        s.pipe.Key.Region,
		ParentEventID: m.ParentEventID,
	})
	out, e := s.sessions.context(ctx, s.roles, awsctx.ServicePrincipal{
		Name: "pipes.amazonaws.com", SourceARN: s.pipe.Key.ARN(),
		Type: "AWSService",
	}, s.pipe.RoleARN, s.pipe.Key.Name, "")
	if e != nil {
		return ctx, &awswire.Error{Code: "AccessDeniedException", Message: e.Error(), StatusCode: 403}
	}
	return out, nil
}
func (a *PipesSources) SQS(ctx context.Context, p pipes.PipeRecord) (lambda.SQSConsumer, *awswire.Error) {
	if a.Queues == nil {
		return nil, pipesDependency("SQS")
	}
	s := &pipesSession{roles: a.Roles, pipe: p}
	if _, e := s.context(ctx); e != nil {
		return nil, e
	}
	return &pipesSQSConsumer{a.Queues, s, p.SourceARN}, nil
}
func (a *PipesSources) Kinesis(ctx context.Context, p pipes.PipeRecord) (lambda.KinesisConsumer, *awswire.Error) {
	if a.KinesisStreams == nil {
		return nil, pipesDependency("Kinesis")
	}
	s := &pipesSession{roles: a.Roles, pipe: p}
	if _, e := s.context(ctx); e != nil {
		return nil, e
	}
	return &pipesKinesisConsumer{a.KinesisStreams, s, p.SourceARN}, nil
}
func (a *PipesSources) DynamoDB(ctx context.Context, p pipes.PipeRecord) (lambda.DynamoDBConsumer, *awswire.Error) {
	if a.DynamoDBStreams == nil {
		return nil, pipesDependency("DynamoDB Streams")
	}
	s := &pipesSession{roles: a.Roles, pipe: p}
	if _, e := s.context(ctx); e != nil {
		return nil, e
	}
	return &pipesDynamoDBConsumer{a.DynamoDBStreams, s, p.SourceARN}, nil
}
func pipesDependency(name string) *awswire.Error {
	return &awswire.Error{Code: "NotImplementedException", Message: name + " requires a real configured execution adapter.", StatusCode: 501}
}

type pipesSQSConsumer struct {
	queues  LambdaSQSQueues
	session *pipesSession
	arn     string
}

func (c *pipesSQSConsumer) Check(ctx context.Context) (lambda.SQSQueueInfo, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return lambda.SQSQueueInfo{}, e
	}
	v, _, e := c.queues.CheckConsumeQueue(ctx, c.arn)
	return lambda.SQSQueueInfo{VisibilitySeconds: v.VisibilitySeconds, FIFO: v.FIFO}, e
}
func (c *pipesSQSConsumer) Receive(ctx context.Context, in *sqsapi.ReceiveMessageInput) (*sqsapi.ReceiveMessageOutput, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return nil, e
	}
	return c.queues.ReceiveFromQueue(ctx, c.arn, in)
}
func (c *pipesSQSConsumer) Delete(ctx context.Context, in *sqsapi.DeleteMessageBatchInput) (*sqsapi.DeleteMessageBatchOutput, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return nil, e
	}
	return c.queues.DeleteFromQueue(ctx, c.arn, in)
}

type pipesKinesisConsumer struct {
	streams LambdaKinesisStreams
	session *pipesSession
	arn     string
}

func (c *pipesKinesisConsumer) Check(ctx context.Context) (*kinesisapi.StreamDescription, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return nil, e
	}
	return c.streams.CheckConsumeStream(ctx, c.arn)
}
func (c *pipesKinesisConsumer) Describe(ctx context.Context, in *kinesisapi.DescribeStreamInput) (*kinesisapi.DescribeStreamOutput, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return nil, e
	}
	return c.streams.DescribeStream(ctx, in)
}
func (c *pipesKinesisConsumer) Iterator(ctx context.Context, in *kinesisapi.GetShardIteratorInput) (*kinesisapi.GetShardIteratorOutput, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return nil, e
	}
	return c.streams.GetShardIterator(ctx, in)
}
func (c *pipesKinesisConsumer) Records(ctx context.Context, in *kinesisapi.GetRecordsInput) (*kinesisapi.GetRecordsOutput, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return nil, e
	}
	return c.streams.GetRecords(ctx, in)
}
func (c *pipesKinesisConsumer) Subscribe(ctx context.Context, in *kinesisapi.SubscribeToShardInput) (*kinesisapi.SubscribeToShardOutput, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return nil, e
	}
	return c.streams.SubscribeToShard(ctx, in)
}
func (c *pipesKinesisConsumer) LatestSequence(ctx context.Context, shard string) (string, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return "", e
	}
	return c.streams.LatestSequence(ctx, c.arn, shard)
}

type pipesDynamoDBConsumer struct {
	streams LambdaDynamoDBStreams
	session *pipesSession
	arn     string
}

func (c *pipesDynamoDBConsumer) Check(ctx context.Context) (*dynamodbapi.StreamDescription, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return nil, e
	}
	return c.streams.CheckConsumeStream(ctx, c.arn)
}
func (c *pipesDynamoDBConsumer) Describe(ctx context.Context, in *dynamodbapi.DescribeStreamInput) (*dynamodbapi.DescribeStreamOutput, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return nil, e
	}
	return c.streams.DescribeStream(ctx, in)
}
func (c *pipesDynamoDBConsumer) Iterator(ctx context.Context, in *dynamodbapi.GetShardIteratorInput) (*dynamodbapi.GetShardIteratorOutput, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return nil, e
	}
	return c.streams.GetShardIterator(ctx, in)
}
func (c *pipesDynamoDBConsumer) Records(ctx context.Context, in *dynamodbapi.GetRecordsInput) (*dynamodbapi.GetRecordsOutput, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return nil, e
	}
	return c.streams.GetRecords(ctx, in)
}
func (c *pipesDynamoDBConsumer) LatestSequence(ctx context.Context, shard string) (string, *awswire.Error) {
	ctx, e := c.session.context(ctx)
	if e != nil {
		return "", e
	}
	return c.streams.LatestSequence(ctx, c.arn, shard)
}
