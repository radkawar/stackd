package integrations

import (
	"context"

	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
	"stackd/internal/services/lambda"
)

// LambdaKinesisStreams retains IAM, positioning, retention and native bytes in
// Kinesis. No engine offsets or source repositories cross this boundary.
type LambdaKinesisStreams interface {
	CheckConsumeStream(context.Context, string) (*api.StreamDescription, *awswire.Error)
	LatestSequence(context.Context, string, string) (string, *awswire.Error)
	DescribeStream(context.Context, *api.DescribeStreamInput) (*api.DescribeStreamOutput, *awswire.Error)
	GetShardIterator(context.Context, *api.GetShardIteratorInput) (*api.GetShardIteratorOutput, *awswire.Error)
	GetRecords(context.Context, *api.GetRecordsInput) (*api.GetRecordsOutput, *awswire.Error)
	SubscribeToShard(context.Context, *api.SubscribeToShardInput) (*api.SubscribeToShardOutput, *awswire.Error)
}

type LambdaKinesis struct {
	Roles   ServiceRoles
	Streams LambdaKinesisStreams
}

func (a LambdaKinesis) Open(ctx context.Context, function lambda.FunctionKey, roleARN, sourceARN string) (lambda.KinesisConsumer, *awswire.Error) {
	session, wire := openLambdaSourceSession(ctx, a.Roles, function, roleARN)
	if wire != nil {
		return nil, wire
	}
	return &lambdaKinesisConsumer{provider: a, session: session, sourceARN: sourceARN}, nil
}

type lambdaKinesisConsumer struct {
	provider  LambdaKinesis
	session   *lambdaSourceSession
	sourceARN string
}

func (c *lambdaKinesisConsumer) Check(ctx context.Context) (*api.StreamDescription, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	return c.provider.Streams.CheckConsumeStream(ctx, c.sourceARN)
}
func (c *lambdaKinesisConsumer) Describe(ctx context.Context, in *api.DescribeStreamInput) (*api.DescribeStreamOutput, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	return c.provider.Streams.DescribeStream(ctx, in)
}
func (c *lambdaKinesisConsumer) Iterator(ctx context.Context, in *api.GetShardIteratorInput) (*api.GetShardIteratorOutput, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	return c.provider.Streams.GetShardIterator(ctx, in)
}
func (c *lambdaKinesisConsumer) Records(ctx context.Context, in *api.GetRecordsInput) (*api.GetRecordsOutput, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	return c.provider.Streams.GetRecords(ctx, in)
}
func (c *lambdaKinesisConsumer) Subscribe(ctx context.Context, in *api.SubscribeToShardInput) (*api.SubscribeToShardOutput, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	return c.provider.Streams.SubscribeToShard(ctx, in)
}
func (c *lambdaKinesisConsumer) LatestSequence(ctx context.Context, shardID string) (string, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return "", wire
	}
	return c.provider.Streams.LatestSequence(ctx, c.sourceARN, shardID)
}
