package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

type cfnLambdaEventInvokeConfig struct{ commands StepFunctionsCommands }

type cfnLambdaEventInvokeProperties struct {
	FunctionName             string
	Qualifier                string
	MaximumEventAgeInSeconds *cfnMessagingInt
	MaximumRetryAttempts     *cfnMessagingInt
	DestinationConfig        *api.DestinationConfig
}

func cfnLambdaEventInvokeInput(p cloudformation.Properties) (*api.PutFunctionEventInvokeConfigInput, error) {
	var properties cfnLambdaEventInvokeProperties
	if err := cfnMessagingDecode(p, &properties); err != nil {
		return nil, err
	}
	if properties.FunctionName == "" || properties.Qualifier == "" {
		return nil, fmt.Errorf("FunctionName and Qualifier are required")
	}
	in := &api.PutFunctionEventInvokeConfigInput{FunctionName: new(api.NamespacedFunctionName(properties.FunctionName)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier(properties.Qualifier)), DestinationConfig: properties.DestinationConfig}
	if value := properties.MaximumEventAgeInSeconds; value != nil {
		if *value < 60 || *value > 21600 {
			return nil, fmt.Errorf("MaximumEventAgeInSeconds must be between 60 and 21600")
		}
		in.MaximumEventAgeInSeconds = new(api.MaximumEventAgeInSeconds(*value))
	}
	if value := properties.MaximumRetryAttempts; value != nil {
		if *value < 0 || *value > 2 {
			return nil, fmt.Errorf("MaximumRetryAttempts must be between 0 and 2")
		}
		// Zero is a requested setting, not an omitted/default value.
		in.MaximumRetryAttempts = new(api.MaximumRetryAttempts(*value))
	}
	if in.MaximumEventAgeInSeconds == nil && in.MaximumRetryAttempts == nil && in.DestinationConfig == nil {
		return nil, fmt.Errorf("at least one event handling or destination setting is required")
	}
	if config := in.DestinationConfig; config != nil {
		if config.OnSuccess != nil && config.OnSuccess.Destination == nil || config.OnFailure != nil && config.OnFailure.Destination == nil {
			return nil, fmt.Errorf("DestinationConfig routes require Destination")
		}
		if config.OnSuccess == nil && config.OnFailure == nil && in.MaximumEventAgeInSeconds == nil && in.MaximumRetryAttempts == nil {
			return nil, fmt.Errorf("DestinationConfig must contain a destination")
		}
	}
	return in, nil
}

func (h cfnLambdaEventInvokeConfig) Validate(p cloudformation.Properties) error {
	_, err := cfnLambdaEventInvokeInput(p)
	return err
}
func (h cfnLambdaEventInvokeConfig) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "FunctionName", "Qualifier"), h.Validate(b)
}
func cfnLambdaEventInvokeResult(out *api.FunctionEventInvokeConfig) (cloudformation.ResourceResult, error) {
	function, qualifier, err := cfnLambdaAdditionalIdentity(cloudformation.ResourceRequest{PhysicalID: cfnComputeValue(out.FunctionArn)}, "FunctionName")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := function + "|" + qualifier
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id}, nil
}
func (h cfnLambdaEventInvokeConfig) put(ctx context.Context, r cloudformation.ResourceRequest, create bool) (cloudformation.ResourceResult, error) {
	in, err := cfnLambdaEventInvokeInput(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	function, qualifier, err := cfnLambdaAdditionalIdentity(r, "FunctionName")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in.FunctionName, in.Qualifier = new(api.NamespacedFunctionName(function)), new(api.NumericLatestPublishedOrAliasQualifier(qualifier))
	// Put replaces the complete configuration, so omitted settings reset to
	// Lambda defaults rather than persisting stale destinations/retry limits.
	out, err := cfnMessagingCall[api.PutFunctionEventInvokeConfigOutput](cfnLambdaAdditionalContext(ctx, r, create), h.commands, "lambda", "PutFunctionEventInvokeConfig", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaEventInvokeResult(out)
}
func (h cfnLambdaEventInvokeConfig) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.put(ctx, r, true)
}
func (h cfnLambdaEventInvokeConfig) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.put(ctx, r, false)
}
func (h cfnLambdaEventInvokeConfig) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	function, qualifier, err := cfnLambdaAdditionalIdentity(r, "FunctionName")
	if err != nil {
		return err
	}
	return cfnComputeAbsent(cfnMessagingExec(cfnLambdaAdditionalContext(ctx, r, false), h.commands, "lambda", "DeleteFunctionEventInvokeConfig", &api.DeleteFunctionEventInvokeConfigInput{FunctionName: new(api.NamespacedFunctionName(function)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier(qualifier))}))
}
func cfnLambdaEventInvokeModel(out *api.FunctionEventInvokeConfig) (cloudformation.Properties, error) {
	properties, err := cfnLambdaAdditionalProperties(out)
	if err != nil {
		return nil, err
	}
	r := cloudformation.ResourceRequest{PhysicalID: cfnComputeValue(out.FunctionArn)}
	function, qualifier, err := cfnLambdaAdditionalIdentity(r, "FunctionName")
	if err != nil {
		return nil, err
	}
	delete(properties, "FunctionArn")
	delete(properties, "LastModified")
	properties["FunctionName"], properties["Qualifier"] = function, qualifier
	if config, ok := properties["DestinationConfig"].(map[string]any); ok {
		for _, route := range []string{"OnSuccess", "OnFailure"} {
			if destination, ok := config[route].(map[string]any); ok && destination["Destination"] == nil {
				delete(config, route)
			}
		}
		if len(config) == 0 {
			delete(properties, "DestinationConfig")
		}
	}
	return properties, nil
}
func (h cfnLambdaEventInvokeConfig) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	function, qualifier, err := cfnLambdaAdditionalIdentity(r, "FunctionName")
	if err != nil {
		return nil, err
	}
	out, err := cfnMessagingCall[api.GetFunctionEventInvokeConfigOutput](cfnLambdaAdditionalContext(ctx, r, false), h.commands, "lambda", "GetFunctionEventInvokeConfig", &api.GetFunctionEventInvokeConfigInput{FunctionName: new(api.NamespacedFunctionName(function)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier(qualifier))})
	if err != nil {
		return nil, err
	}
	return cfnLambdaEventInvokeModel(out)
}
func (h cfnLambdaEventInvokeConfig) listFunction(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	function := cfnComputeString(r.Properties, "FunctionName")
	if function == "" {
		return nil, fmt.Errorf("FunctionName is required for EventInvokeConfig listing")
	}
	in := &api.ListFunctionEventInvokeConfigsInput{FunctionName: new(api.NamespacedFunctionName(function))}
	rows := []cloudformation.ResourceDescription{}
	for {
		out, err := cfnMessagingCall[api.ListFunctionEventInvokeConfigsOutput](ctx, h.commands, "lambda", "ListFunctionEventInvokeConfigs", in)
		if err != nil {
			return nil, err
		}
		for _, config := range out.FunctionEventInvokeConfigs {
			properties, err := cfnLambdaEventInvokeModel(&config)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: cfnComputeString(properties, "FunctionName") + "|" + cfnComputeString(properties, "Qualifier"), Properties: properties})
		}
		if cfnComputeValue(out.NextMarker) == "" {
			return rows, nil
		}
		in.Marker = out.NextMarker
	}
}

func (h cfnLambdaEventInvokeConfig) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	if _, err := cfnLambdaRequiredListFilter(r, "FunctionName"); err != nil {
		return nil, err
	}
	return h.listFunction(ctx, r)
}
