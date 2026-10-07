package integrations

import (
	"context"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

func (h cfnDynamoDBTable) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	table, err := h.describe(cfnDDBOwnerContext(ctx, r, true), cfnComputeName(r, "TableName", 255))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnDDBTableResult(table), nil
}

func (h cfnDynamoDBGlobalTable) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	table, err := h.table().describe(cfnDDBOwnerContext(ctx, r, true), cfnComputeName(r, "TableName", 255))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnDDBGlobalResult(table), nil
}

func (h cfnKinesisStream) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	stream, err := h.describe(cfnKinesisOwnerContext(ctx, r, "stream", true), cfnComputeName(r, "Name", 128))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnKinesisStreamResult(stream), nil
}

func (h cfnKinesisConsumer) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	consumer, err := h.describe(cfnKinesisOwnerContext(ctx, r, "consumer", true), map[string]any{"StreamARN": cfnComputeString(r.Properties, "StreamARN"), "ConsumerName": cfnComputeString(r.Properties, "ConsumerName")})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnKinesisConsumerResult(consumer), nil
}

func (h cfnKinesisResourcePolicy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	arn := cfnComputeString(r.Properties, "ResourceArn")
	if err := cfnMessagingScopeARN(r, arn, "kinesis"); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	policy, err := h.current(cfnKinesisOwnerContext(ctx, r, "policy", true), arn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if policy == "" {
		return cloudformation.ResourceResult{}, &awswire.Error{Code: "ResourceNotFoundException", Message: "No resource policy found", StatusCode: 400}
	}
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn}, nil
}
