package integrations

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
	service "stackd/internal/services/lambda"
)

type cfnLambdaMapping struct{ commands StepFunctionsCommands }

func cfnLambdaMappingContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return service.WithMappingOwner(ctx, service.MappingOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}, r.PhysicalID)
}

func (h cfnLambdaMapping) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "FunctionName", "EventSourceArn", "BatchSize", "Enabled", "MaximumBatchingWindowInSeconds", "FunctionResponseTypes", "ScalingConfig", "Tags", "StartingPosition", "StartingPositionTimestamp", "ParallelizationFactor", "MaximumRetryAttempts", "MaximumRecordAgeInSeconds", "BisectBatchOnFunctionError", "TumblingWindowInSeconds", "DestinationConfig", "FilterCriteria", "MetricsConfig", "KmsKeyArn", "SelfManagedEventSource", "SelfManagedKafkaEventSourceConfig", "AmazonManagedKafkaEventSourceConfig", "Topics", "SourceAccessConfigurations", "DocumentDBEventSourceConfig", "Queues"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "FunctionName"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "FunctionName", "EventSourceArn", "StartingPosition", "KmsKeyArn"); err != nil {
		return err
	}
	source := "self-managed-kafka"
	if _, selfManaged := p["SelfManagedEventSource"]; !selfManaged {
		parsed, err := arn.Parse(cfnComputeString(p, "EventSourceArn"))
		if err != nil || (parsed.Service != "sqs" && parsed.Service != "kinesis" && parsed.Service != "dynamodb" && parsed.Service != "kafka" && parsed.Service != "rds" && parsed.Service != "mq") {
			return fmt.Errorf("CloudFormation event source mappings support SQS, Kinesis, DynamoDB Streams, MSK, self-managed Kafka, DocumentDB and Amazon MQ sources")
		}
		source = parsed.Service
	} else if _, present := p["EventSourceArn"]; present {
		return fmt.Errorf("SelfManagedEventSource and EventSourceArn are mutually exclusive")
	}
	if source == "kinesis" || source == "dynamodb" {
		if err := cfnComputeRequired(p, "StartingPosition"); err != nil {
			return err
		}
	}
	if err := cfnLambdaMappingSettings(p, source); err != nil {
		return err
	}
	if err := cfnLambdaMappingKafkaSettings(p, source); err != nil {
		return err
	}
	if _, err := cfnComputeStringList(p, "FunctionResponseTypes"); err != nil {
		return err
	}
	if value, found := p["ScalingConfig"]; found {
		object, ok := cfnComputeObject(value)
		if !ok {
			return fmt.Errorf("ScalingConfig must be an object")
		}
		if err := cfnComputeProperties(object, "MaximumConcurrency"); err != nil {
			return err
		}
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnLambdaMapping) Replacement(a, b cloudformation.Properties) (bool, error) {
	plan, err := h.ReplacementPlan(a, b)
	if err != nil || plan == "True" {
		return plan == "True", err
	}
	// A create-only change replaces before Update. Otherwise native Update
	// rejects changed Topics before considering consumer-group replacement.
	if cfnComputeChanged(a, b, "Topics") {
		return false, nil
	}
	return cfnLambdaMappingKafkaGroup(a) != cfnLambdaMappingKafkaGroup(b), nil
}

func (h cfnLambdaMapping) ReplacementPlan(a, b cloudformation.Properties) (string, error) {
	if err := h.Validate(b); err != nil {
		return "", err
	}
	// Native plans report no recreation for a consumer-group edit even though
	// execution creates a new mapping. Keep that public plan separate.
	if cfnComputeChanged(a, b, "EventSourceArn", "StartingPosition", "StartingPositionTimestamp", "SelfManagedEventSource") {
		return "True", nil
	}
	return "False", nil
}
func (h cfnLambdaMapping) owned(ctx context.Context, r cloudformation.ResourceRequest, id string) (*api.EventSourceMappingConfiguration, error) {
	out, err := cfnComputeCall[api.GetEventSourceMappingOutput](cfnLambdaMappingContext(ctx, r, false), h.commands, "lambda", "GetEventSourceMapping", map[string]any{"UUID": id})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func cfnLambdaMappingResult(mapping *api.EventSourceMappingConfiguration) cloudformation.ResourceResult {
	id := cfnComputeValue(mapping.UUID)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id, "EventSourceMappingArn": cfnComputeValue(mapping.EventSourceMappingArn)}}
}
func (h cfnLambdaMapping) find(ctx context.Context, r cloudformation.ResourceRequest) (*api.EventSourceMappingConfiguration, error) {
	if r.PhysicalID != "" {
		return h.owned(ctx, r, r.PhysicalID)
	}
	if r.CloudControl {
		return nil, fmt.Errorf("a mapping identifier is required")
	}
	ctx = cfnLambdaMappingContext(ctx, r, false)
	marker := ""
	for {
		input := map[string]any{}
		if marker != "" {
			input["Marker"] = marker
		}
		out, err := cfnComputeCall[api.ListEventSourceMappingsOutput](ctx, h.commands, "lambda", "ListEventSourceMappings", input)
		if err != nil {
			return nil, err
		}
		for _, mapping := range out.EventSourceMappings {
			return h.owned(ctx, r, cfnComputeValue(mapping.UUID))
		}
		marker = cfnComputeValue(out.NextMarker)
		if marker == "" {
			return nil, nil
		}
	}
}
func (h cfnLambdaMapping) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cloudformation.ValidateResourceStringLengths(r.Type, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnLambdaMappingCreateInput(r.Properties)
	if cfnLambdaMappingKafkaConfig(r.Properties) != "" {
		input["StartingPosition"] = cfnComputeDefault(r.Properties, "StartingPosition", "TRIM_HORIZON")
	}
	if source, present := cfnComputeObject(r.Properties["SelfManagedEventSource"]); present {
		endpoints, _ := cfnComputeObject(source["Endpoints"])
		input["SelfManagedEventSource"] = map[string]any{
			"Endpoints": map[string]any{"KAFKA_BOOTSTRAP_SERVERS": endpoints["KafkaBootstrapServers"]},
		}
	}
	if value, present := input["StartingPositionTimestamp"]; present {
		timestamp, err := cfnLambdaMappingTimestamp(value)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		input["StartingPositionTimestamp"] = timestamp
	}
	input["Tags"] = cfnLambdaDeploymentTags(r)
	mapping, err := cfnComputeCall[api.CreateEventSourceMappingOutput](cfnLambdaMappingContext(ctx, r, true), h.commands, "lambda", "CreateEventSourceMapping", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaMappingResult(mapping), nil
}
func (h cfnLambdaMapping) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cloudformation.ValidateResourceStringLengths(r.Type, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	mapping, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnLambdaMappingKafkaUpdate(mapping, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnLambdaMappingMQUpdate(mapping, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaMappingResult(mapping), nil
}
func (h cfnLambdaMapping) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnLambdaMappingContext(ctx, r, false)
	mapping, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return false, err
	}
	state := cfnComputeValue(mapping.State)
	if state == "Failed" {
		return false, fmt.Errorf("event source mapping failed: %s", cfnComputeValue(mapping.StateTransitionReason))
	}
	if state != "Enabled" && state != "Disabled" {
		return false, nil
	}
	arn := cfnComputeValue(mapping.EventSourceMappingArn)
	current, err := cfnLambdaTags(ctx, h.commands, arn)
	if err != nil {
		return false, err
	}
	desired := cfnLambdaPhaseTags(r)
	key := cfnComputeTagPrefix + "mapping"
	if current[key] != desired[key] {
		input := cfnLambdaMappingUpdateInput(r)
		if err := cfnComputeRun(ctx, h.commands, "lambda", "UpdateEventSourceMapping", input); err != nil {
			return false, err
		}
		return false, cfnComputeRun(ctx, h.commands, "lambda", "TagResource", map[string]any{"Resource": arn, "Tags": desired})
	}
	if err := cfnLambdaSyncTags(ctx, h.commands, r, arn); err != nil {
		return false, err
	}
	return true, nil
}
func (h cfnLambdaMapping) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	mapping, err := h.find(ctx, r)
	if cfnComputeMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return mapping == nil, nil
}
func (h cfnLambdaMapping) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnLambdaMappingContext(ctx, r, false)
	mapping, err := h.find(ctx, r)
	if err != nil {
		return cfnComputeAbsent(err)
	}
	if mapping == nil {
		return nil
	}
	id := cfnComputeValue(mapping.UUID)
	if cfnComputeValue(mapping.State) != "Deleting" {
		if err := cfnComputeRun(ctx, h.commands, "lambda", "DeleteEventSourceMapping", map[string]any{"UUID": id}); err != nil {
			return cfnComputeAbsent(err)
		}
	}
	return nil
}
