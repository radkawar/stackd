package integrations

import (
	"context"
	"strings"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

func (h cfnLambdaMapping) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ctx = cfnLambdaMappingContext(ctx, r, false)
	id := r.PhysicalID
	if id == "" {
		id = cfnComputeString(r.Properties, "Id")
	}
	out, err := cfnComputeCall[api.GetEventSourceMappingOutput](ctx, h.commands, "lambda", "GetEventSourceMapping", map[string]any{"UUID": id})
	if err != nil {
		return nil, err
	}
	if out.FilterCriteriaError != nil {
		return nil, &awswire.Error{Code: cfnComputeValue(out.FilterCriteriaError.ErrorCode), Message: cfnComputeValue(out.FilterCriteriaError.Message), StatusCode: 400}
	}
	tags, err := cfnLambdaTags(ctx, h.commands, cfnComputeValue(out.EventSourceMappingArn))
	if err != nil {
		return nil, err
	}
	model, err := cfnLambdaAdditionalProperties(out)
	if err != nil {
		return nil, err
	}
	properties := cloudformation.Properties(cfnComputeCopy(model, "StartingPosition", "SelfManagedEventSource", "ParallelizationFactor", "FilterCriteria", "ProvisionedPollerConfig", "MetricsConfig", "DestinationConfig", "AmazonManagedKafkaEventSourceConfig", "SourceAccessConfigurations", "MaximumBatchingWindowInSeconds", "BatchSize", "MaximumRetryAttempts", "Topics", "ScalingConfig", "EventSourceArn", "SelfManagedKafkaEventSourceConfig", "DocumentDBEventSourceConfig", "TumblingWindowInSeconds", "BisectBatchOnFunctionError", "EventSourceMappingArn", "MaximumRecordAgeInSeconds", "StartingPositionTimestamp", "LoggingConfig", "Queues", "FunctionResponseTypes"))
	properties["FunctionName"] = cfnComputeValue(out.FunctionArn)
	properties["Id"] = cfnComputeValue(out.UUID)
	switch cfnComputeValue(out.State) {
	case "Enabled", "Enabling":
		properties["Enabled"] = true
	case "Disabled", "Disabling":
		properties["Enabled"] = false
	}
	if kms := cfnComputeValue(out.KMSKeyArn); kms != "" {
		properties["KmsKeyArn"] = kms
	}
	userTags := []any{}
	for _, key := range cfnMessagingKeys(tags) {
		if !strings.HasPrefix(key, cfnComputeTagPrefix) {
			userTags = append(userTags, map[string]any{"Key": key, "Value": tags[key]})
		}
	}
	if len(userTags) > 0 {
		properties["Tags"] = userTags
	}
	return properties, nil
}
func (h cfnLambdaMapping) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	ctx = cfnLambdaMappingContext(ctx, r, false)
	input := cfnComputeCopy(r.Properties, "EventSourceArn", "FunctionName")
	rows := []cloudformation.ResourceDescription{}
	for {
		out, err := cfnComputeCall[api.ListEventSourceMappingsOutput](ctx, h.commands, "lambda", "ListEventSourceMappings", input)
		if err != nil {
			return nil, err
		}
		for _, mapping := range out.EventSourceMappings {
			request := r
			request.PhysicalID = cfnComputeValue(mapping.UUID)
			properties, err := h.Read(ctx, request)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: request.PhysicalID, Properties: properties})
		}
		if cfnComputeValue(out.NextMarker) == "" {
			return rows, nil
		}
		input["Marker"] = cfnComputeValue(out.NextMarker)
	}
}
