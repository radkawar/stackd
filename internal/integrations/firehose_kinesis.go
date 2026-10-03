package integrations

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/firehose"
)

// FirehoseKinesisCommands uses public Kinesis positions and current IAM checks;
// no physical engine offsets or resource repositories cross this boundary.
type FirehoseKinesisCommands interface {
	DescribeStream(context.Context, *api.DescribeStreamInput) (*api.DescribeStreamOutput, *awswire.Error)
	GetShardIterator(context.Context, *api.GetShardIteratorInput) (*api.GetShardIteratorOutput, *awswire.Error)
	GetRecords(context.Context, *api.GetRecordsInput) (*api.GetRecordsOutput, *awswire.Error)
}

type FirehoseKinesis struct {
	Roles    ServiceRoles
	Streams  FirehoseKinesisCommands
	sessions serviceRoleSessions
}

func (a *FirehoseKinesis) context(ctx context.Context, key firehose.StreamKey, source firehose.KinesisSourceRecord) (context.Context, *awswire.Error) {
	if source.Created.IsZero() {
		credential, rejected := a.Roles.assume(ctx, firehosePrincipal(key), source.RoleARN, identity.RoleSessionSpec{SessionName: "Firehose"}, key.AccountID)
		if rejected != nil {
			return ctx, firehoseAssumptionError(source.RoleARN, rejected)
		}
		return serviceRoleRequestContext(ctx, credential, key.Region, "firehose.amazonaws.com")
	}
	ctx, err := a.sessions.context(ctx, a.Roles, firehosePrincipal(key), source.RoleARN, "Firehose", key.AccountID)
	if err != nil {
		return ctx, serviceRoleFailure(err)
	}
	return ctx, nil
}
func (a *FirehoseKinesis) Describe(ctx context.Context, key firehose.StreamKey, source firehose.KinesisSourceRecord) (*api.StreamDescription, *awswire.Error) {
	parsed, err := arn.Parse(source.ARN)
	if err != nil || parsed.Service != "kinesis" || !strings.HasPrefix(parsed.Resource, "stream/") || parsed.Partition != key.Partition || parsed.Region != key.Region {
		return nil, &awswire.Error{Code: "InvalidArgumentException", Message: "The Kinesis source ARN must identify a stream in the same partition and Region.", StatusCode: 400}
	}
	ctx, rejected := a.context(ctx, key, source)
	if rejected != nil {
		return nil, rejected
	}
	input := &api.DescribeStreamInput{StreamARN: new(api.StreamARN(source.ARN)), Limit: new(api.DescribeStreamInputLimit(10000))}
	var result *api.StreamDescription
	for {
		out, rejected := a.Streams.DescribeStream(ctx, input)
		if rejected != nil {
			if rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException" {
				return nil, &awswire.Error{Code: "AccessDeniedException", Message: "Role " + source.RoleARN + " is not authorized to perform: kinesis:DescribeStream on resource " + source.ARN + ".", StatusCode: 400}
			}
			return nil, rejected
		}
		page := out.StreamDescription
		if result == nil {
			result = page
		} else {
			result.Shards = append(result.Shards, page.Shards...)
		}
		if page.HasMoreShards == nil || !bool(*page.HasMoreShards) {
			result.HasMoreShards = new(api.BooleanObject(false))
			return result, nil
		}
		input.ExclusiveStartShardId = page.Shards[len(page.Shards)-1].ShardId
	}
}
func (a *FirehoseKinesis) Iterator(ctx context.Context, key firehose.StreamKey, source firehose.KinesisSourceRecord, input *api.GetShardIteratorInput) (*api.GetShardIteratorOutput, *awswire.Error) {
	ctx, rejected := a.context(ctx, key, source)
	if rejected != nil {
		return nil, rejected
	}
	return a.Streams.GetShardIterator(ctx, input)
}
func (a *FirehoseKinesis) Records(ctx context.Context, key firehose.StreamKey, source firehose.KinesisSourceRecord, input *api.GetRecordsInput) (*api.GetRecordsOutput, *awswire.Error) {
	ctx, rejected := a.context(ctx, key, source)
	if rejected != nil {
		return nil, rejected
	}
	return a.Streams.GetRecords(ctx, input)
}
