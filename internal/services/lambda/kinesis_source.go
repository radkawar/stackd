package lambda

import (
	"context"

	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
)

// KinesisSource opens platform reads under the current execution role, without
// customer-runtime lambda:SourceFunctionArn credentials.
type KinesisSource interface {
	Open(context.Context, FunctionKey, string, string) (KinesisConsumer, *awswire.Error)
}

// KinesisConsumer preserves generated source commands and opaque checkpoints.
// Check resolves either a stream ARN or its registered consumer ARN under the
// source's current authority, without requiring DescribeStreamConsumer.
type KinesisConsumer interface {
	Check(context.Context) (*api.StreamDescription, *awswire.Error)
	Describe(context.Context, *api.DescribeStreamInput) (*api.DescribeStreamOutput, *awswire.Error)
	Iterator(context.Context, *api.GetShardIteratorInput) (*api.GetShardIteratorOutput, *awswire.Error)
	Records(context.Context, *api.GetRecordsInput) (*api.GetRecordsOutput, *awswire.Error)
	Subscribe(context.Context, *api.SubscribeToShardInput) (*api.SubscribeToShardOutput, *awswire.Error)
	LatestSequence(context.Context, string) (string, *awswire.Error)
}
