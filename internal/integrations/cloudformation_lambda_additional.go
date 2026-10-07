package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/lambda"
)

// CloudFormationLambdaAdditionalHandlers exposes only native resource types
// implemented by the Lambda command owner. Registration is explicit, not init.
func CloudFormationLambdaAdditionalHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::Lambda::EventInvokeConfig": cfnLambdaEventInvokeConfig{commands},
		"AWS::Lambda::Url":               cfnLambdaURL{commands},
		"AWS::Lambda::CodeSigningConfig": cfnLambdaCodeSigningConfig{commands},
		"AWS::Lambda::CapacityProvider":  cfnLambdaCapacityProvider{commands},
	}
}

func cfnLambdaAdditionalContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return lambda.WithAdditionalOwner(ctx, lambda.AdditionalOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}, create)
}

// Physical identity is authoritative during replacement cleanup. Both qualified
// and unqualified function ARNs are supported; desired names never retarget it.
func cfnLambdaAdditionalIdentity(r cloudformation.ResourceRequest, property string) (string, string, error) {
	if r.PhysicalID == "" {
		return cfnComputeString(r.Properties, property), cfnComputeString(r.Properties, "Qualifier"), nil
	}
	if property == "FunctionName" {
		if function, qualifier, compound := strings.Cut(r.PhysicalID, "|"); compound {
			if function == "" || qualifier == "" || strings.Contains(qualifier, "|") {
				return "", "", fmt.Errorf("identifier must contain FunctionName and Qualifier")
			}
			return function, qualifier, nil
		}
	}
	parsed, err := arn.Parse(r.PhysicalID)
	resource, ok := strings.CutPrefix(parsed.Resource, "function:")
	if err != nil || parsed.Service != "lambda" || !ok || resource == "" {
		return "", "", fmt.Errorf("identifier must be a Lambda function ARN")
	}
	name, qualifier, _ := strings.Cut(resource, ":")
	if name == "" || strings.Contains(qualifier, ":") {
		return "", "", fmt.Errorf("identifier must be a Lambda function ARN")
	}
	parsed.Resource = "function:" + name
	return parsed.String(), qualifier, nil
}

func cfnLambdaAdditionalProperties(value any) (cloudformation.Properties, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var properties cloudformation.Properties
	err = json.Unmarshal(body, &properties)
	return properties, err
}

func cfnLambdaAdditionalTags(ctx context.Context, commands StepFunctionsCommands, id string) (map[string]string, error) {
	out, err := cfnMessagingCall[api.ListTagsOutput](ctx, commands, "lambda", "ListTags", &api.ListTagsInput{Resource: new(api.TaggableResource(id))})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(out.Tags))
	for key, value := range out.Tags {
		tags[string(key)] = string(value)
	}
	return tags, nil
}

// Native Lambda CFN tag schemas require Key but allow an omitted Value. Normalize
// only that omission, then reuse the common tag validation/ownership convention.
func cfnLambdaAdditionalTagProperties(p cloudformation.Properties) (cloudformation.Properties, error) {
	raw, present := p["Tags"]
	if !present {
		return p, nil
	}
	tags, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("tags must be a list")
	}
	var normalized []any
	for i, raw := range tags {
		tag, ok := cfnComputeObject(raw)
		if !ok {
			return nil, fmt.Errorf("tags entries must be objects")
		}
		if _, present := tag["Value"]; !present {
			if normalized == nil {
				normalized = append([]any{}, tags...)
			}
			copy := maps.Clone(tag)
			copy["Value"] = ""
			normalized[i] = copy
		}
	}
	if normalized != nil {
		p = maps.Clone(p)
		p["Tags"] = normalized
	}
	if _, err := cfnComputeTags(p); err != nil {
		return nil, err
	}
	return p, nil
}

func cfnLambdaAdditionalUpdateTags(ctx context.Context, commands StepFunctionsCommands, r cloudformation.ResourceRequest, id string) error {
	current, err := cfnLambdaAdditionalTags(ctx, commands, id)
	if err != nil {
		return err
	}
	normalized, err := cfnLambdaAdditionalTagProperties(r.Properties)
	if err != nil {
		return err
	}
	r.Properties = normalized
	desired := cfnResourceTags(r)
	add := api.Tags{}
	remove := api.TagKeyList{}
	for key, value := range desired {
		if old, present := current[key]; !present || old != value {
			add[api.TagKey(key)] = api.TagValue(value)
		}
	}
	for key := range current {
		if _, present := desired[key]; !present {
			remove = append(remove, api.TagKey(key))
		}
	}
	if len(add) > 0 {
		if err := cfnMessagingExec(ctx, commands, "lambda", "TagResource", &api.TagResourceInput{Resource: new(api.TaggableResource(id)), Tags: add}); err != nil {
			return err
		}
	}
	if len(remove) > 0 {
		return cfnMessagingExec(ctx, commands, "lambda", "UntagResource", &api.UntagResourceInput{Resource: new(api.TaggableResource(id)), TagKeys: remove})
	}
	return nil
}

func cfnLambdaAdditionalAPITags(r cloudformation.ResourceRequest) (api.Tags, error) {
	normalized, err := cfnLambdaAdditionalTagProperties(r.Properties)
	if err != nil {
		return nil, err
	}
	r.Properties = normalized
	tags := api.Tags{}
	for key, value := range cfnResourceTags(r) {
		tags[api.TagKey(key)] = api.TagValue(value)
	}
	return tags, nil
}

func cfnLambdaRequiredListFilter(r cloudformation.ResourceRequest, property string) (string, error) {
	value := cfnComputeString(r.Properties, property)
	if value == "" {
		return "", &awswire.Error{Code: "InvalidParameterValueException", Message: property + " is required by the native resource list handler.", StatusCode: 400}
	}
	return value, nil
}

func cfnLambdaAdditionalFunctions(ctx context.Context, commands StepFunctionsCommands) ([]string, error) {
	in := &api.ListFunctionsInput{}
	functions := []string{}
	for {
		out, err := cfnMessagingCall[api.ListFunctionsOutput](ctx, commands, "lambda", "ListFunctions", in)
		if err != nil {
			return nil, err
		}
		for _, function := range out.Functions {
			functions = append(functions, cfnComputeValue(function.FunctionArn))
		}
		if cfnComputeValue(out.NextMarker) == "" {
			return functions, nil
		}
		in.Marker = out.NextMarker
	}
}
