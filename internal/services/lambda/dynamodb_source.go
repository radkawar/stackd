package lambda

import (
	"context"

	api "stackd/internal/awsapi/dynamodbstreams"
	"stackd/internal/awswire"
)

// DynamoDBSource opens a stream consumer under the function's execution role.
// Source reads are platform calls and do not carry lambda:SourceFunctionArn.
// Stream state, retention and current permissions remain DynamoDB-owned.
type DynamoDBSource interface {
	Open(ctx context.Context, function FunctionKey, roleARN, sourceARN string) (DynamoDBConsumer, *awswire.Error)
}

// DynamoDBConsumer keeps the generated stream command types at the integration
// boundary. Check evaluates admission permissions without synthetic API calls.
type DynamoDBConsumer interface {
	Check(context.Context) (*api.StreamDescription, *awswire.Error)
	Describe(context.Context, *api.DescribeStreamInput) (*api.DescribeStreamOutput, *awswire.Error)
	Iterator(context.Context, *api.GetShardIteratorInput) (*api.GetShardIteratorOutput, *awswire.Error)
	Records(context.Context, *api.GetRecordsInput) (*api.GetRecordsOutput, *awswire.Error)
	// LatestSequence returns the durable shard high-water, including trimmed history.
	LatestSequence(context.Context, string) (string, *awswire.Error)
}
