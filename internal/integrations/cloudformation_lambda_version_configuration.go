package integrations

import (
	"context"
	"fmt"
	"math"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

func cfnLambdaVersionRuntime(p cloudformation.Properties) (map[string]any, error) {
	raw, present := p["RuntimePolicy"]
	if !present {
		return nil, nil
	}
	object, ok := cfnComputeObject(raw)
	if !ok {
		return nil, fmt.Errorf("RuntimePolicy must be an object")
	}
	if err := cfnComputeProperties(object, "UpdateRuntimeOn", "RuntimeVersionArn"); err != nil {
		return nil, err
	}
	if err := cfnComputeRequired(object, "UpdateRuntimeOn"); err != nil {
		return nil, err
	}
	if err := cfnComputeStrings(object, "UpdateRuntimeOn", "RuntimeVersionArn"); err != nil {
		return nil, err
	}
	return object, nil
}

func cfnLambdaVersionScaling(p cloudformation.Properties) (map[string]any, error) {
	raw, present := p["FunctionScalingConfig"]
	if !present {
		return nil, nil
	}
	object, ok := cfnComputeObject(raw)
	if !ok {
		return nil, fmt.Errorf("FunctionScalingConfig must be an object")
	}
	var config struct {
		MinExecutionEnvironments *cfnMessagingInt
		MaxExecutionEnvironments *cfnMessagingInt
	}
	if err := cfnMessagingDecode(object, &config); err != nil {
		return nil, err
	}
	out := make(map[string]any, 2)
	for _, field := range [...]struct {
		name  string
		value *cfnMessagingInt
	}{{"MinExecutionEnvironments", config.MinExecutionEnvironments}, {"MaxExecutionEnvironments", config.MaxExecutionEnvironments}} {
		if field.value == nil {
			continue
		}
		if *field.value < 0 || *field.value > math.MaxInt32 {
			return nil, fmt.Errorf("%s must be a nonnegative 32-bit integer", field.name)
		}
		out[field.name] = int32(*field.value)
	}
	return out, nil
}

func (h cfnLambdaVersion) scaling(ctx context.Context, r cloudformation.ResourceRequest) error {
	config, err := cfnLambdaVersionScaling(r.Properties)
	if err != nil {
		return err
	}
	_, previous := r.Previous["FunctionScalingConfig"]
	if config == nil && !previous {
		return nil
	}
	function, version, err := cfnLambdaVersionIdentity(r)
	if err != nil {
		return err
	}
	input := map[string]any{"FunctionName": function, "Qualifier": version}
	if config != nil {
		input["FunctionScalingConfig"] = config
	}
	return cfnComputeRun(cfnLambdaVersionContext(ctx, r), h.commands, "lambda", "PutFunctionScalingConfig", input)
}

func (h cfnLambdaVersion) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	function, version, err := cfnLambdaVersionIdentity(r)
	if err != nil {
		return false, err
	}
	ctx = cfnLambdaVersionContext(ctx, r)
	input := map[string]any{"FunctionName": function, "Qualifier": version}
	configuration, err := cfnComputeCall[api.GetFunctionConfigurationOutput](ctx, h.commands, "lambda", "GetFunctionConfiguration", input)
	if err != nil {
		return false, err
	}
	switch cfnComputeValue(configuration.State) {
	case "Failed":
		return false, fmt.Errorf("lambda version activation failed: %s", cfnComputeValue(configuration.StateReason))
	case "Active", "ActiveNonInvocable":
	default:
		return false, nil
	}
	runtime, err := cfnLambdaVersionRuntime(r.Properties)
	if err != nil {
		return false, err
	}
	if runtime != nil {
		current, err := cfnComputeCall[api.GetRuntimeManagementConfigOutput](ctx, h.commands, "lambda", "GetRuntimeManagementConfig", input)
		if err != nil {
			return false, err
		}
		if cfnComputeValue(current.UpdateRuntimeOn) != cfnComputeString(runtime, "UpdateRuntimeOn") || cfnComputeValue(current.RuntimeVersionArn) != cfnComputeString(runtime, "RuntimeVersionArn") {
			update := cfnComputeCopy(runtime, "UpdateRuntimeOn", "RuntimeVersionArn")
			update["FunctionName"], update["Qualifier"] = function, version
			if err := cfnComputeRun(ctx, h.commands, "lambda", "PutRuntimeManagementConfig", update); err != nil {
				return false, err
			}
		}
	}
	requested, present, err := cfnLambdaProvisioned(r.Properties)
	if err != nil {
		return false, err
	}
	return cfnLambdaStabilizeProvisioned(ctx, h.commands, function, version, requested, present, false)
}
