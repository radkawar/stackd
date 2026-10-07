package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

type cfnLambdaCapacityProvider struct{ commands StepFunctionsCommands }

func cfnLambdaCapacityScaling(raw any) (*api.CapacityProviderScalingConfig, error) {
	object, ok := cfnComputeObject(raw)
	if !ok {
		return nil, fmt.Errorf("CapacityProviderScalingConfig must be an object")
	}
	var properties struct {
		MaxVCpuCount    *cfnMessagingInt
		ScalingMode     *api.CapacityProviderScalingMode
		ScalingPolicies []struct {
			PredefinedMetricType *api.CapacityProviderPredefinedMetricType
			TargetValue          *json.Number
		}
	}
	if err := cfnMessagingDecode(object, &properties); err != nil {
		return nil, err
	}
	out := &api.CapacityProviderScalingConfig{ScalingMode: properties.ScalingMode}
	if properties.MaxVCpuCount != nil {
		if *properties.MaxVCpuCount < 2 || *properties.MaxVCpuCount > 15000 {
			return nil, fmt.Errorf("MaxVCpuCount must be between 2 and 15000")
		}
		out.MaxVCpuCount = new(api.CapacityProviderMaxVCpuCount(*properties.MaxVCpuCount))
	}
	if out.ScalingMode != nil && *out.ScalingMode != "Auto" && *out.ScalingMode != "Manual" {
		return nil, fmt.Errorf("ScalingMode must be Auto or Manual")
	}
	if properties.ScalingPolicies != nil {
		if len(properties.ScalingPolicies) < 1 || len(properties.ScalingPolicies) > 10 {
			return nil, fmt.Errorf("ScalingPolicies requires 1 to 10 entries")
		}
		out.ScalingPolicies = make(api.CapacityProviderScalingPoliciesList, len(properties.ScalingPolicies))
		for i, policy := range properties.ScalingPolicies {
			if policy.PredefinedMetricType == nil || policy.TargetValue == nil {
				return nil, fmt.Errorf("scaling policies require PredefinedMetricType and TargetValue")
			}
			target, err := policy.TargetValue.Float64()
			if err != nil || math.IsNaN(target) || math.IsInf(target, 0) || target < 0 {
				return nil, fmt.Errorf("TargetValue must be a nonnegative finite number")
			}
			out.ScalingPolicies[i] = api.TargetTrackingScalingPolicy{PredefinedMetricType: policy.PredefinedMetricType, TargetValue: new(api.MetricTargetValue(target))}
		}
	}
	return out, nil
}

func cfnLambdaCapacityInput(p cloudformation.Properties) (*api.CreateCapacityProviderRequest, error) {
	if err := cfnComputeProperties(p, "CapacityProviderName", "CapacityProviderScalingConfig", "InstanceRequirements", "KmsKeyArn", "PermissionsConfig", "PropagateTags", "Tags", "TelemetryConfig", "VpcConfig"); err != nil {
		return nil, err
	}
	if _, err := cfnLambdaAdditionalTagProperties(p); err != nil {
		return nil, err
	}
	properties := cfnComputeCopy(p, "CapacityProviderName", "InstanceRequirements", "KmsKeyArn", "PermissionsConfig", "PropagateTags", "TelemetryConfig", "VpcConfig")
	if raw, found := properties["PropagateTags"]; found {
		config, ok := cfnComputeObject(raw)
		if !ok {
			return nil, fmt.Errorf("PropagateTags must be an object")
		}
		if err := cfnComputeProperties(config, "Mode", "ExplicitTags"); err != nil {
			return nil, err
		}
		copy := cfnComputeCopy(config, "Mode")
		if tags, found := config["ExplicitTags"]; found {
			normalized, err := cfnLambdaAdditionalTagProperties(cloudformation.Properties{"Tags": tags})
			if err != nil {
				return nil, err
			}
			values, err := cfnComputeTags(normalized)
			if err != nil {
				return nil, err
			}
			copy["ExplicitTags"] = values
		}
		properties["PropagateTags"] = copy
	}
	var in api.CreateCapacityProviderRequest
	if err := cfnMessagingDecode(properties, &in); err != nil {
		return nil, err
	}
	if raw, present := p["CapacityProviderScalingConfig"]; present {
		scaling, err := cfnLambdaCapacityScaling(raw)
		if err != nil {
			return nil, err
		}
		in.CapacityProviderScalingConfig = scaling
	}
	if in.PermissionsConfig == nil || cfnComputeValue(in.PermissionsConfig.CapacityProviderOperatorRoleArn) == "" {
		return nil, fmt.Errorf("PermissionsConfig.CapacityProviderOperatorRoleArn is required")
	}
	if in.VpcConfig == nil || len(in.VpcConfig.SubnetIds) == 0 || in.VpcConfig.SecurityGroupIds == nil {
		return nil, fmt.Errorf("VpcConfig requires SubnetIds and SecurityGroupIds")
	}
	// The actual owner explicitly rejects unimplemented telemetry, GPU policies,
	// or absent managed-EC2 backends. The adapter does not fake those effects.
	return &in, nil
}
func (h cfnLambdaCapacityProvider) Validate(p cloudformation.Properties) error {
	_, err := cfnLambdaCapacityInput(p)
	return err
}
func (h cfnLambdaCapacityProvider) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "CapacityProviderName", "VpcConfig", "InstanceRequirements", "PermissionsConfig", "KmsKeyArn"), h.Validate(b)
}
func cfnLambdaCapacityName(r cloudformation.ResourceRequest) string {
	return cfnComputeName(r, "CapacityProviderName", 140)
}
func cfnLambdaCapacityResult(config *api.CapacityProvider) (cloudformation.ResourceResult, error) {
	if config == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("lambda returned no CapacityProvider")
	}
	arn := cfnComputeValue(config.CapacityProviderArn)
	index := strings.LastIndex(arn, ":capacity-provider:")
	if index < 0 {
		return cloudformation.ResourceResult{}, fmt.Errorf("lambda returned an invalid capacity provider ARN")
	}
	name := arn[index+len(":capacity-provider:"):]
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": arn, "State": cfnComputeValue(config.State)}}, nil
}
func (h cfnLambdaCapacityProvider) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	in, err := cfnLambdaCapacityInput(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in.CapacityProviderName = new(api.CapacityProviderName(cfnLambdaCapacityName(r)))
	in.Tags, err = cfnLambdaAdditionalAPITags(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnMessagingCall[api.CreateCapacityProviderResponse](cfnLambdaAdditionalContext(ctx, r, true), h.commands, "lambda", "CreateCapacityProvider", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaCapacityResult(out.CapacityProvider)
}
func (h cfnLambdaCapacityProvider) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	properties, err := cfnLambdaCapacityInput(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnLambdaAdditionalContext(ctx, r, false)
	in := &api.UpdateCapacityProviderRequest{CapacityProviderName: new(api.CapacityProviderName(cfnLambdaCapacityName(r))), CapacityProviderScalingConfig: properties.CapacityProviderScalingConfig, PropagateTags: properties.PropagateTags, TelemetryConfig: properties.TelemetryConfig}
	if in.CapacityProviderScalingConfig == nil {
		in.CapacityProviderScalingConfig = &api.CapacityProviderScalingConfig{}
	}
	if in.CapacityProviderScalingConfig.ScalingMode == nil {
		in.CapacityProviderScalingConfig.ScalingMode = new(api.CapacityProviderScalingMode("Auto"))
	}
	if in.CapacityProviderScalingConfig.MaxVCpuCount == nil {
		in.CapacityProviderScalingConfig.MaxVCpuCount = new(api.CapacityProviderMaxVCpuCount(400))
	}
	if in.CapacityProviderScalingConfig.ScalingPolicies == nil {
		in.CapacityProviderScalingConfig.ScalingPolicies = api.CapacityProviderScalingPoliciesList{{PredefinedMetricType: new(api.CapacityProviderPredefinedMetricType("LambdaCapacityProviderAverageCPUUtilization")), TargetValue: new(api.MetricTargetValue(50))}}
	}
	if in.PropagateTags == nil {
		in.PropagateTags = &api.PropagateTags{Mode: new(api.PropagateTagsMode("None"))}
	}
	out, err := cfnMessagingCall[api.UpdateCapacityProviderResponse](ctx, h.commands, "lambda", "UpdateCapacityProvider", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if out.CapacityProvider == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("lambda returned no CapacityProvider")
	}
	if err := cfnLambdaAdditionalUpdateTags(ctx, h.commands, r, cfnComputeValue(out.CapacityProvider.CapacityProviderArn)); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaCapacityResult(out.CapacityProvider)
}
func (h cfnLambdaCapacityProvider) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return cfnComputeAbsent(cfnMessagingExec(cfnLambdaAdditionalContext(ctx, r, false), h.commands, "lambda", "DeleteCapacityProvider", &api.DeleteCapacityProviderRequest{CapacityProviderName: new(api.CapacityProviderName(cfnLambdaCapacityName(r)))}))
}
func (h cfnLambdaCapacityProvider) get(ctx context.Context, r cloudformation.ResourceRequest) (*api.CapacityProvider, error) {
	out, err := cfnMessagingCall[api.GetCapacityProviderResponse](cfnLambdaAdditionalContext(ctx, r, false), h.commands, "lambda", "GetCapacityProvider", &api.GetCapacityProviderRequest{CapacityProviderName: new(api.CapacityProviderName(cfnLambdaCapacityName(r)))})
	if err != nil {
		return nil, err
	}
	if out.CapacityProvider == nil {
		return nil, fmt.Errorf("lambda returned no CapacityProvider")
	}
	return out.CapacityProvider, nil
}
func (h cfnLambdaCapacityProvider) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	config, err := h.get(ctx, r)
	if err != nil {
		return false, err
	}
	switch cfnComputeValue(config.State) {
	case "Active":
		return true, nil
	case "Failed":
		return false, fmt.Errorf("lambda capacity provider failed")
	default:
		return false, nil
	}
}
func (h cfnLambdaCapacityProvider) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.get(ctx, r)
	if cfnComputeMissing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnLambdaCapacityProvider) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	config, err := h.get(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaCapacityResult(config)
}
func (h cfnLambdaCapacityProvider) model(ctx context.Context, config *api.CapacityProvider) (cloudformation.Properties, error) {
	properties, err := cfnLambdaAdditionalProperties(config)
	if err != nil {
		return nil, err
	}
	result, err := cfnLambdaCapacityResult(config)
	if err != nil {
		return nil, err
	}
	properties["CapacityProviderName"], properties["Arn"] = result.PhysicalID, cfnComputeValue(config.CapacityProviderArn)
	delete(properties, "CapacityProviderArn")
	delete(properties, "LastModified")
	if vpc, ok := properties["VpcConfig"].(map[string]any); ok && vpc["SecurityGroupIds"] == nil {
		vpc["SecurityGroupIds"] = []any{}
	}
	if propagate, ok := properties["PropagateTags"].(map[string]any); ok {
		if config.PropagateTags != nil && config.PropagateTags.ExplicitTags != nil {
			tags := map[string]string{}
			for key, value := range config.PropagateTags.ExplicitTags {
				tags[string(key)] = string(value)
			}
			propagate["ExplicitTags"] = cfnResourcePublicTags(tags)
		}
	}
	tags, err := cfnLambdaAdditionalTags(ctx, h.commands, cfnComputeValue(config.CapacityProviderArn))
	if err != nil {
		return nil, err
	}
	properties["Tags"] = cfnResourcePublicTags(tags)
	return properties, nil
}
func (h cfnLambdaCapacityProvider) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	config, err := h.get(ctx, r)
	if err != nil {
		return nil, err
	}
	return h.model(cfnLambdaAdditionalContext(ctx, r, false), config)
}
func (h cfnLambdaCapacityProvider) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	in := &api.ListCapacityProvidersRequest{}
	if state := cfnComputeString(r.Properties, "State"); state != "" {
		in.State = new(api.CapacityProviderState(state))
	}
	rows := []cloudformation.ResourceDescription{}
	for {
		out, err := cfnMessagingCall[api.ListCapacityProvidersResponse](ctx, h.commands, "lambda", "ListCapacityProviders", in)
		if err != nil {
			return nil, err
		}
		for _, config := range out.CapacityProviders {
			properties, err := h.model(ctx, &config)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: cfnComputeString(properties, "CapacityProviderName"), Properties: properties})
		}
		if cfnComputeValue(out.NextMarker) == "" {
			return rows, nil
		}
		in.Marker = out.NextMarker
	}
}
