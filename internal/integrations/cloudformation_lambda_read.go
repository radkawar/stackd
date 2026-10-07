package integrations

import (
	"context"
	"fmt"
	"sort"
	"strings"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

func (h cfnLambdaFunction) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	function, _, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnLambdaResult(function)
	result.PhysicalID = r.PhysicalID
	return result, nil
}
func (h cfnLambdaFunction) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name := r.PhysicalID
	if name == "" {
		name = cfnComputeString(r.Properties, "FunctionName")
	}
	if name == "" {
		return nil, fmt.Errorf("FunctionName is required")
	}
	out, err := cfnComputeCall[api.GetFunctionOutput](cfnLambdaFunctionContext(ctx, r, false), h.commands, "lambda", "GetFunction", map[string]any{"FunctionName": name})
	if err != nil {
		return nil, err
	}
	if out.Configuration == nil {
		return nil, fmt.Errorf("lambda returned no function configuration")
	}
	configuration, err := cfnLambdaAdditionalProperties(out.Configuration)
	if err != nil {
		return nil, err
	}
	properties := cloudformation.Properties(cfnComputeCopy(configuration, "FunctionName", "PackageType", "Runtime", "Handler", "Role", "Description", "Timeout", "MemorySize", "Environment", "Architectures", "EphemeralStorage", "DeadLetterConfig", "LoggingConfig", "TracingConfig", "DurableConfig"))
	properties["Arn"] = cfnComputeValue(out.Configuration.FunctionArn)
	if response, ok := cfnComputeObject(configuration["ImageConfigResponse"]); ok {
		if image, found := response["ImageConfig"]; found {
			properties["ImageConfig"] = image
		}
	}
	if vpc, ok := cfnComputeObject(configuration["VpcConfig"]); ok {
		properties["VpcConfig"] = cfnComputeCopy(vpc, "SubnetIds", "SecurityGroupIds", "Ipv6AllowedForDualStack")
	}
	if len(out.Configuration.Layers) > 0 {
		layers := []string{}
		for _, layer := range out.Configuration.Layers {
			layers = append(layers, cfnComputeValue(layer.Arn))
		}
		properties["Layers"] = layers
	}
	if out.Concurrency != nil && out.Concurrency.ReservedConcurrentExecutions != nil {
		properties["ReservedConcurrentExecutions"] = int(*out.Concurrency.ReservedConcurrentExecutions)
	}
	keys := make([]string, 0, len(out.Tags))
	for key := range out.Tags {
		if !strings.HasPrefix(string(key), cfnComputeTagPrefix) {
			keys = append(keys, string(key))
		}
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		tags := []any{}
		for _, key := range keys {
			tags = append(tags, map[string]any{"Key": key, "Value": string(out.Tags[api.TagKey(key)])})
		}
		properties["Tags"] = tags
	}
	signing, err := cfnComputeCall[api.GetFunctionCodeSigningConfigOutput](cfnLambdaFunctionContext(ctx, r, false), h.commands, "lambda", "GetFunctionCodeSigningConfig", map[string]any{"FunctionName": name})
	if err != nil {
		return nil, err
	}
	if arn := cfnComputeValue(signing.CodeSigningConfigArn); arn != "" {
		properties["CodeSigningConfigArn"] = arn
	}
	// Code is write-only in the regional provider schema. A live GetFunction
	// projection is not a license to invent the original ZIP source properties.
	return properties, nil
}
func (h cfnLambdaFunction) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	names, err := cfnLambdaAdditionalFunctions(ctx, h.commands)
	if err != nil {
		return nil, err
	}
	rows := []cloudformation.ResourceDescription{}
	for _, name := range names {
		request := r
		request.PhysicalID = name
		properties, err := h.Read(ctx, request)
		if cfnComputeMissing(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		identifier, err := cloudformation.ResourceIdentifier("AWS::Lambda::Function", properties)
		if err != nil {
			return nil, err
		}
		rows = append(rows, cloudformation.ResourceDescription{Identifier: identifier, Properties: properties})
	}
	return rows, nil
}
