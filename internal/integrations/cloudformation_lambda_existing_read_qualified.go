package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

func cfnLambdaExistingProvisioned(ctx context.Context, commands StepFunctionsCommands, function, qualifier string, properties cloudformation.Properties) error {
	out, err := cfnComputeCall[api.GetProvisionedConcurrencyConfigOutput](ctx, commands, "lambda", "GetProvisionedConcurrencyConfig", map[string]any{"FunctionName": function, "Qualifier": qualifier})
	if cfnMessagingMissing(err, "ProvisionedConcurrencyConfigNotFoundException") {
		return nil
	}
	if err != nil {
		return err
	}
	if out.RequestedProvisionedConcurrentExecutions != nil {
		properties["ProvisionedConcurrencyConfig"] = map[string]any{"ProvisionedConcurrentExecutions": int32(*out.RequestedProvisionedConcurrentExecutions)}
	}
	return nil
}

func (h cfnLambdaAlias) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	function, name, err := cfnLambdaQualifiedIdentity(r)
	if err != nil {
		return nil, err
	}
	ctx = cfnLambdaAliasContext(ctx, r)
	out, err := cfnComputeCall[api.GetAliasOutput](ctx, h.commands, "lambda", "GetAlias", map[string]any{"FunctionName": function, "Name": name})
	if err != nil {
		return nil, err
	}
	properties := cloudformation.Properties{"FunctionName": function, "Name": cfnComputeValue(out.Name), "AliasArn": cfnComputeValue(out.AliasArn), "FunctionVersion": cfnComputeValue(out.FunctionVersion), "Description": cfnComputeValue(out.Description)}
	if out.RoutingConfig != nil && len(out.RoutingConfig.AdditionalVersionWeights) > 0 {
		weights := make([]any, 0, len(out.RoutingConfig.AdditionalVersionWeights))
		for _, version := range cfnMessagingKeys(out.RoutingConfig.AdditionalVersionWeights) {
			weights = append(weights, map[string]any{"FunctionVersion": string(version), "FunctionWeight": float64(out.RoutingConfig.AdditionalVersionWeights[version])})
		}
		properties["RoutingConfig"] = map[string]any{"AdditionalVersionWeights": weights}
	}
	if err := cfnLambdaExistingProvisioned(ctx, h.commands, function, name, properties); err != nil {
		return nil, err
	}
	return properties, nil
}
func (h cfnLambdaAlias) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	function, err := cfnLambdaRequiredListFilter(r, "FunctionName")
	if err != nil {
		return nil, err
	}
	functions := []string{function}
	rows := []cloudformation.ResourceDescription{}
	for _, function := range functions {
		input := map[string]any{"FunctionName": function}
		for {
			out, err := cfnComputeCall[api.ListAliasesOutput](ctx, h.commands, "lambda", "ListAliases", input)
			if err != nil {
				return nil, err
			}
			for _, alias := range out.Aliases {
				request := r
				request.PhysicalID = cfnComputeValue(alias.AliasArn)
				properties, err := h.Read(ctx, request)
				if err != nil {
					return nil, err
				}
				rows = append(rows, cloudformation.ResourceDescription{Identifier: request.PhysicalID, Properties: properties})
			}
			if cfnComputeValue(out.NextMarker) == "" {
				break
			}
			input["Marker"] = cfnComputeValue(out.NextMarker)
		}
	}
	return rows, nil
}

func (h cfnLambdaVersion) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	function, version, err := cfnLambdaVersionIdentity(r)
	if err != nil {
		return nil, err
	}
	ctx = cfnLambdaVersionContext(ctx, r)
	input := map[string]any{"FunctionName": function, "Qualifier": version}
	out, err := cfnComputeCall[api.GetFunctionConfigurationOutput](ctx, h.commands, "lambda", "GetFunctionConfiguration", input)
	if err != nil {
		return nil, err
	}
	properties := cloudformation.Properties{"FunctionName": function, "FunctionArn": cfnComputeValue(out.FunctionArn), "Version": cfnComputeValue(out.Version), "CodeSha256": cfnComputeValue(out.CodeSha256), "Description": cfnComputeValue(out.Description)}
	if cfnComputeValue(out.PackageType) != "Image" {
		runtime, err := cfnComputeCall[api.GetRuntimeManagementConfigOutput](ctx, h.commands, "lambda", "GetRuntimeManagementConfig", input)
		if err != nil {
			return nil, err
		}
		policy := map[string]any{"UpdateRuntimeOn": cfnComputeValue(runtime.UpdateRuntimeOn)}
		if cfnComputeValue(runtime.RuntimeVersionArn) != "" {
			policy["RuntimeVersionArn"] = cfnComputeValue(runtime.RuntimeVersionArn)
		}
		properties["RuntimePolicy"] = policy
	}
	if out.CapacityProviderConfig != nil {
		scaling, err := cfnComputeCall[api.GetFunctionScalingConfigOutput](ctx, h.commands, "lambda", "GetFunctionScalingConfig", input)
		if err != nil {
			return nil, err
		}
		if scaling.RequestedFunctionScalingConfig != nil {
			model, err := cfnLambdaAdditionalProperties(scaling.RequestedFunctionScalingConfig)
			if err != nil {
				return nil, err
			}
			properties["FunctionScalingConfig"] = model
		}
	}
	if err := cfnLambdaExistingProvisioned(ctx, h.commands, function, version, properties); err != nil {
		return nil, err
	}
	return properties, nil
}
func (h cfnLambdaVersion) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	function, err := cfnLambdaRequiredListFilter(r, "FunctionName")
	if err != nil {
		return nil, err
	}
	functions := []string{function}
	rows := []cloudformation.ResourceDescription{}
	for _, function := range functions {
		input := map[string]any{"FunctionName": function}
		for {
			out, err := cfnComputeCall[api.ListVersionsByFunctionOutput](ctx, h.commands, "lambda", "ListVersionsByFunction", input)
			if err != nil {
				return nil, err
			}
			for _, version := range out.Versions {
				if cfnComputeValue(version.Version) == "$LATEST" {
					continue
				}
				request := r
				request.PhysicalID = cfnComputeValue(version.FunctionArn)
				if request.PhysicalID == "" {
					return nil, fmt.Errorf("lambda returned a version without its ARN")
				}
				properties, err := h.Read(ctx, request)
				if err != nil {
					return nil, err
				}
				rows = append(rows, cloudformation.ResourceDescription{Identifier: request.PhysicalID, Properties: properties})
			}
			if cfnComputeValue(out.NextMarker) == "" {
				break
			}
			input["Marker"] = cfnComputeValue(out.NextMarker)
		}
	}
	return rows, nil
}
