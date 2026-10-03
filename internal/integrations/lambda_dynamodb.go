package integrations

import (
	"context"

	api "stackd/internal/awsapi/dynamodbstreams"
	"stackd/internal/awswire"
	"stackd/internal/services/lambda"
)

// LambdaDynamoDBStreams keeps generation, record retention and IAM in DynamoDB.
type LambdaDynamoDBStreams interface {
	CheckConsumeStream(context.Context, string) (*api.StreamDescription, *awswire.Error)
	LatestSequence(context.Context, string, string) (string, *awswire.Error)
	DescribeStream(context.Context, *api.DescribeStreamInput) (*api.DescribeStreamOutput, *awswire.Error)
	GetShardIterator(context.Context, *api.GetShardIteratorInput) (*api.GetShardIteratorOutput, *awswire.Error)
	GetRecords(context.Context, *api.GetRecordsInput) (*api.GetRecordsOutput, *awswire.Error)
}

// LambdaDynamoDB supplies source consumers without granting the caller or the
// runtime direct access to the native engine or its private cursor encoding.
type LambdaDynamoDB struct {
	Roles   ServiceRoles
	Streams LambdaDynamoDBStreams
}

func (a LambdaDynamoDB) Open(ctx context.Context, function lambda.FunctionKey, roleARN, sourceARN string) (lambda.DynamoDBConsumer, *awswire.Error) {
	session, wire := openLambdaSourceSession(ctx, a.Roles, function, roleARN)
	if wire != nil {
		return nil, wire
	}
	return &lambdaDynamoDBConsumer{provider: a, session: session, sourceARN: sourceARN}, nil
}

type lambdaDynamoDBConsumer struct {
	provider  LambdaDynamoDB
	session   *lambdaSourceSession
	sourceARN string
}

func (c *lambdaDynamoDBConsumer) Check(ctx context.Context) (*api.StreamDescription, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	out, wire := c.provider.Streams.CheckConsumeStream(ctx, c.sourceARN)
	if wire != nil && wire.StatusCode == 403 {
		return nil, &awswire.Error{Code: "InvalidParameterValueException", Message: "Cannot access stream " + c.sourceARN + ". Please ensure the role can perform the GetRecords, GetShardIterator, DescribeStream, and ListStreams Actions on your stream in IAM.", StatusCode: 400, Type: "User"}
	}
	return out, wire
}

func (c *lambdaDynamoDBConsumer) Describe(ctx context.Context, in *api.DescribeStreamInput) (*api.DescribeStreamOutput, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	return c.provider.Streams.DescribeStream(ctx, in)
}

func (c *lambdaDynamoDBConsumer) Iterator(ctx context.Context, in *api.GetShardIteratorInput) (*api.GetShardIteratorOutput, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	return c.provider.Streams.GetShardIterator(ctx, in)
}

func (c *lambdaDynamoDBConsumer) Records(ctx context.Context, in *api.GetRecordsInput) (*api.GetRecordsOutput, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	return c.provider.Streams.GetRecords(ctx, in)
}

func (c *lambdaDynamoDBConsumer) LatestSequence(ctx context.Context, shardID string) (string, *awswire.Error) {
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return "", wire
	}
	return c.provider.Streams.LatestSequence(ctx, c.sourceARN, shardID)
}
