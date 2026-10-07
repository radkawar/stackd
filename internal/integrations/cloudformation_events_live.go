package integrations

import (
	"context"
	"encoding/json"
	"strings"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/services/cloudformation"
)

func cfnEventRuleIdentity(r cloudformation.ResourceRequest) cloudformation.ResourceRequest {
	if bus, _, qualified := strings.Cut(r.PhysicalID, "|"); r.CloudControl && qualified {
		properties := cloudformation.Properties{}
		for key, value := range r.Properties {
			properties[key] = value
		}
		properties["EventBusName"] = bus
		r.Properties = properties
	}
	return r
}

// Read/List reconstruct the CFN model from the native EventBridge authority,
// including native-created resources. They never consult controller state.
func (h cfnEventBus) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := cfnComputeCall[api.DescribeEventBusOutput](ctx, h.commands, "eventbridge", "DescribeEventBus", map[string]any{"Name": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	properties, err := cfnWorkflowProjection(out, "Name", "Arn", "Description", "KmsKeyIdentifier", "DeadLetterConfig", "Policy")
	if err != nil {
		return nil, err
	}
	tags, err := cfnEventTags(ctx, h.commands, cfnComputeValue(out.Arn))
	if err != nil {
		return nil, err
	}
	properties["Tags"] = cfnWorkflowUserTags(tags)
	if policy, ok := properties["Policy"].(string); ok && policy == "" {
		delete(properties, "Policy")
	}
	return properties, nil
}
func (h cfnEventBus) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListEventBusesOutput](ctx, h.commands, "eventbridge", "ListEventBuses", input)
		if err != nil {
			return nil, err
		}
		for _, bus := range out.EventBuses {
			rr := r
			rr.PhysicalID = cfnComputeValue(bus.Name)
			properties, err := h.Read(ctx, rr)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: properties})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnEventRule) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	r = cfnEventRuleIdentity(r)
	name, bus := cfnEventRuleName(r), cfnEventRuleBus(r.Properties)
	out, err := cfnComputeCall[api.DescribeRuleOutput](ctx, h.commands, "eventbridge", "DescribeRule", map[string]any{"Name": name, "EventBusName": bus})
	if err != nil {
		return nil, err
	}
	properties, err := cfnWorkflowProjection(out, "Name", "Arn", "Description", "EventPattern", "ScheduleExpression", "State", "RoleArn")
	if err != nil {
		return nil, err
	}
	properties["EventBusName"] = bus
	properties["RuleName"] = name
	if pattern, ok := properties["EventPattern"].(string); ok {
		var document any
		if err := json.Unmarshal([]byte(pattern), &document); err != nil {
			return nil, err
		}
		properties["EventPattern"] = document
	}
	tags, err := cfnEventTags(ctx, h.commands, cfnComputeValue(out.Arn))
	if err != nil {
		return nil, err
	}
	properties["Tags"] = cfnWorkflowUserTags(tags)
	targets := []any{}
	input := map[string]any{"Rule": name, "EventBusName": bus}
	for {
		page, err := cfnComputeCall[api.ListTargetsByRuleOutput](ctx, h.commands, "eventbridge", "ListTargetsByRule", input)
		if err != nil {
			return nil, err
		}
		for _, target := range page.Targets {
			model, err := cfnWorkflowProjection(target, "Id", "Arn", "RoleArn", "Input", "InputPath", "InputTransformer", "RetryPolicy", "DeadLetterConfig", "SqsParameters", "HttpParameters", "KinesisParameters", "EcsParameters")
			if err != nil {
				return nil, err
			}
			if ecs, ok := cfnComputeObject(model["EcsParameters"]); ok {
				if value, ok := ecs["PlacementStrategy"]; ok {
					ecs["PlacementStrategies"] = value
					delete(ecs, "PlacementStrategy")
				}
				if value, ok := ecs["Tags"]; ok {
					ecs["TagList"] = value
					delete(ecs, "Tags")
				}
				if network, ok := cfnComputeObject(ecs["NetworkConfiguration"]); ok {
					if value, ok := network["AwsvpcConfiguration"]; ok {
						network["AwsVpcConfiguration"] = value
						delete(network, "AwsvpcConfiguration")
					}
				}
			}
			targets = append(targets, model)
		}
		if cfnComputeValue(page.NextToken) == "" {
			break
		}
		input["NextToken"] = cfnComputeValue(page.NextToken)
	}
	properties["Targets"] = targets
	return properties, nil
}
func (h cfnEventRule) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	buses := map[string]any{}
	for {
		page, err := cfnComputeCall[api.ListEventBusesOutput](ctx, h.commands, "eventbridge", "ListEventBuses", buses)
		if err != nil {
			return nil, err
		}
		for _, bus := range page.EventBuses {
			busName := cfnComputeValue(bus.Name)
			rules := map[string]any{"EventBusName": busName}
			for {
				page, err := cfnComputeCall[api.ListRulesOutput](ctx, h.commands, "eventbridge", "ListRules", rules)
				if err != nil {
					return nil, err
				}
				for _, rule := range page.Rules {
					rr := r
					rr.PhysicalID = cfnComputeValue(rule.Name)
					if busName != "default" {
						rr.PhysicalID = busName + "|" + rr.PhysicalID
					}
					rr.Properties = cloudformation.Properties{"EventBusName": busName}
					properties, err := h.Read(ctx, rr)
					if err != nil {
						return nil, err
					}
					result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: properties})
				}
				if cfnComputeValue(page.NextToken) == "" {
					break
				}
				rules["NextToken"] = cfnComputeValue(page.NextToken)
			}
		}
		if cfnComputeValue(page.NextToken) == "" {
			return result, nil
		}
		buses["NextToken"] = cfnComputeValue(page.NextToken)
	}
}
