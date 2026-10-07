package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/cloudformation"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// CloudFormationStackHandlers delegates the official stack resource to the same
// native stack owner as SDK CreateStack/UpdateStack/DeleteStack. No second stack
// store or synthetic stack completion exists in this adapter.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudformation-stack.html
func CloudFormationStackHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{"AWS::CloudFormation::Stack": cfnStack{commands}}
}

type cfnStack struct{ commands StepFunctionsCommands }

func (h cfnStack) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "StackName", "TemplateBody", "TemplateURL", "Parameters", "Capabilities", "Tags", "RoleARN", "DisableRollback", "EnableTerminationProtection"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "StackName", "TemplateURL", "RoleARN"); err != nil {
		return err
	}
	if _, exists := p["StackName"]; exists && cfnComputeString(p, "StackName") == "" {
		return fmt.Errorf("StackName must be nonempty")
	}
	body, hasBody := p["TemplateBody"]
	url, hasURL := p["TemplateURL"]
	if hasBody == hasURL {
		return fmt.Errorf("exactly one TemplateBody or TemplateURL is required")
	}
	if hasBody {
		switch value := body.(type) {
		case string:
			if value == "" {
				return fmt.Errorf("TemplateBody must be nonempty")
			}
		case map[string]any:
		default:
			return fmt.Errorf("TemplateBody must be an object or string")
		}
	}
	if hasURL && url == "" {
		return fmt.Errorf("TemplateURL must be nonempty")
	}
	if value, exists := p["Parameters"]; exists {
		parameters, ok := cfnComputeObject(value)
		if !ok {
			return fmt.Errorf("parameters must be an object")
		}
		for key, value := range parameters {
			if _, ok := value.(string); !ok || key == "" {
				return fmt.Errorf("parameters requires nonempty keys and string values")
			}
		}
	}
	caps, err := cfnComputeStringList(p, "Capabilities")
	if err != nil {
		return err
	}
	for _, capability := range caps {
		if capability != "CAPABILITY_IAM" && capability != "CAPABILITY_NAMED_IAM" && capability != "CAPABILITY_AUTO_EXPAND" {
			return fmt.Errorf("unsupported capability %s", capability)
		}
	}
	for _, key := range []string{"DisableRollback", "EnableTerminationProtection"} {
		if value, exists := p[key]; exists {
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("%s must be a boolean", key)
			}
		}
	}
	_, err = cfnComputeTags(p)
	return err
}

func (h cfnStack) Replacement(before, after cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(before, after, "StackName"), h.Validate(after)
}

func (h cfnStack) ValidateDeletionPolicy(policy string) error {
	switch policy {
	case "", "Delete", "Retain", "RetainExceptOnCreate":
		return nil
	default:
		return fmt.Errorf("AWS::CloudFormation::Stack does not support %s deletion", policy)
	}
}

func cfnStackContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	ctx = cloudformation.WithStackResourceOperation(ctx)
	if !r.CloudControl {
		ctx = cloudformation.WithNestedStackOwnership(ctx, cloudformation.NestedStackOwnership{ParentID: r.StackID, LogicalID: r.LogicalID, Incarnation: r.Token})
	}
	return ctx
}

func cfnStackToken(r cloudformation.ResourceRequest, operation string) string {
	parts := []any{r.StackID, r.LogicalID, r.Token, operation}
	if operation != "CREATE" {
		parts = append(parts, r.OperationToken)
	}
	if operation == "UPDATE" {
		// Forward update and rollback can share a parent operation, but must not
		// reuse a native request token for different update payloads.
		parts = append(parts, r.Properties, r.Tags)
	}
	body, _ := json.Marshal(parts)
	digest := sha256.Sum256(body)
	return fmt.Sprintf("cfn-%x", digest)
}

func cfnStackMissing(err error) bool {
	var rejected *awswire.Error
	return errors.As(err, &rejected) && rejected.Code == "ValidationError" && strings.HasPrefix(rejected.Message, "Stack with id ") && strings.HasSuffix(rejected.Message, " does not exist")
}

func (h cfnStack) describe(ctx context.Context, r cloudformation.ResourceRequest) (api.Stack, cloudformation.StackResourceObservation, error) {
	var observation cloudformation.StackResourceObservation
	ctx = cloudformation.WithStackResourceObservation(cfnStackContext(ctx, r), &observation)
	out, err := cfnComputeCall[api.DescribeStacksOutput](ctx, h.commands, "cloudformation", "DescribeStacks", map[string]any{"StackName": r.PhysicalID})
	if err != nil {
		return api.Stack{}, observation, err
	}
	if len(out.Stacks) != 1 {
		return api.Stack{}, observation, fmt.Errorf("DescribeStacks did not identify exactly one stack")
	}
	return out.Stacks[0], observation, nil
}

func cfnStackResult(stack api.Stack) cloudformation.ResourceResult {
	id := cfnComputeValue(stack.StackId)
	attributes := map[string]any{"StackId": id, "StackStatus": cfnComputeValue(stack.StackStatus), "Outputs": cfnStackOutputs(stack.Outputs)}
	for _, output := range stack.Outputs {
		attributes["Outputs."+cfnComputeValue(output.OutputKey)] = cfnComputeValue(output.OutputValue)
	}
	if stack.ParentId != nil {
		attributes["ParentId"] = cfnComputeValue(stack.ParentId)
		attributes["RootId"] = cfnComputeValue(stack.RootId)
	}
	if stack.CreationTime != nil {
		attributes["CreationTime"] = stack.CreationTime.UTC().Format(time.RFC3339Nano)
	}
	if stack.LastUpdatedTime != nil {
		attributes["LastUpdateTime"] = stack.LastUpdatedTime.UTC().Format(time.RFC3339Nano)
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: attributes}
}

func cfnStackOutputs(outputs api.Outputs) []any {
	result := make([]any, 0, len(outputs))
	for _, output := range outputs {
		item := map[string]any{"OutputKey": cfnComputeValue(output.OutputKey), "OutputValue": cfnComputeValue(output.OutputValue)}
		if output.Description != nil {
			item["Description"] = cfnComputeValue(output.Description)
		}
		if output.ExportName != nil {
			item["ExportName"] = cfnComputeValue(output.ExportName)
		}
		result = append(result, item)
	}
	return result
}

func (h cfnStack) input(r cloudformation.ResourceRequest) (map[string]any, error) {
	if err := h.Validate(r.Properties); err != nil {
		return nil, err
	}
	if !r.CloudControl {
		for _, key := range []string{"StackName", "Capabilities", "RoleARN", "DisableRollback", "EnableTerminationProtection"} {
			if _, present := r.Properties[key]; present {
				return nil, fmt.Errorf("%s is configured by the parent stack and cannot be set on a nested stack resource", key)
			}
		}
	} else if cfnComputeString(r.Properties, "StackName") == "" {
		return nil, fmt.Errorf("StackName is required for a direct Cloud Control stack")
	}
	in := cfnComputeCopy(r.Properties, "StackName", "TemplateURL", "Capabilities", "RoleARN", "DisableRollback")
	if value, exists := r.Properties["TemplateBody"]; exists {
		if body, ok := value.(string); ok {
			in["TemplateBody"] = body
		} else {
			body, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			in["TemplateBody"] = string(body)
		}
	}
	parameters := []any{}
	if values, ok := cfnComputeObject(r.Properties["Parameters"]); ok {
		for _, key := range slices.Sorted(maps.Keys(values)) {
			parameters = append(parameters, map[string]any{"ParameterKey": key, "ParameterValue": values[key]})
		}
	}
	in["Parameters"] = parameters
	tags, err := cfnComputeTags(r.Properties)
	if err != nil {
		return nil, err
	}
	for key, value := range r.Tags {
		if _, override := tags[key]; !override {
			tags[key] = value
		}
	}
	in["Tags"] = cfnComputeTagList(tags)
	return in, nil
}

func (h cfnStack) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	in, err := h.input(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if !r.CloudControl {
		naming := r
		naming.PhysicalID = ""
		in["StackName"] = cfnComputeName(naming, "StackName", 128)
	}
	if r.Token == "" {
		return cloudformation.ResourceResult{}, fmt.Errorf("stack create requires a retained incarnation token")
	}
	if value, exists := r.Properties["EnableTerminationProtection"]; exists {
		in["EnableTerminationProtection"] = value
	}
	in["ClientRequestToken"] = cfnStackToken(r, "CREATE")
	out, err := cfnComputeCall[api.CreateStackOutput](cfnStackContext(ctx, r), h.commands, "cloudformation", "CreateStack", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeValue(out.StackId)
	// Admission retains the physical identity before another stack job runs.
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"StackId": id}}, nil
}

func (h cfnStack) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	in, err := h.input(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if r.OperationToken == "" {
		return cloudformation.ResourceResult{}, fmt.Errorf("stack update requires a retained operation token")
	}
	if cfnComputeChanged(r.Previous, r.Properties, "StackName") {
		return cloudformation.ResourceResult{}, fmt.Errorf("StackName is immutable and requires replacement")
	}
	ctx = cfnStackContext(ctx, r)
	in["StackName"] = r.PhysicalID
	in["ClientRequestToken"] = cfnStackToken(r, "UPDATE")
	_, err = cfnComputeCall[api.UpdateStackOutput](ctx, h.commands, "cloudformation", "UpdateStack", in)
	if err != nil {
		var rejected *awswire.Error
		if !errors.As(err, &rejected) || rejected.Code != "ValidationError" || rejected.Message != "No updates are to be performed." {
			return cloudformation.ResourceResult{}, err
		}
	}
	if value, exists := r.Properties["EnableTerminationProtection"]; exists && cfnComputeChanged(r.Previous, r.Properties, "EnableTerminationProtection") {
		if err = cfnComputeRun(ctx, h.commands, "cloudformation", "UpdateTerminationProtection", map[string]any{"StackName": r.PhysicalID, "EnableTerminationProtection": value}); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	return cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID, Attributes: map[string]any{"StackId": r.PhysicalID}}, nil
}

func (h cfnStack) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := h.ValidateDeletionPolicy(r.DeletionPolicy); err != nil {
		return err
	}
	return cfnComputeRun(cfnStackContext(ctx, r), h.commands, "cloudformation", "DeleteStack", map[string]any{"StackName": r.PhysicalID, "ClientRequestToken": cfnStackToken(r, "DELETE")})
}

func (h cfnStack) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	stack, operation, err := h.describe(ctx, r)
	if err != nil {
		return false, err
	}
	status := cfnComputeValue(stack.StackStatus)
	if strings.HasSuffix(status, "_IN_PROGRESS") {
		return false, nil
	}
	switch status {
	case "CREATE_COMPLETE", "UPDATE_COMPLETE":
		return true, nil
	case "UPDATE_ROLLBACK_COMPLETE":
		// A no-op restoration is successful only when this is an older native
		// operation. The current child update's rollback is an actual failure.
		if operation.OperationToken != cfnStackToken(r, "UPDATE") {
			return true, nil
		}
	}
	return false, fmt.Errorf("child stack %s reached %s: %s", r.PhysicalID, status, cfnComputeValue(stack.StackStatusReason))
}

func (h cfnStack) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	stack, _, err := h.describe(ctx, r)
	if cfnStackMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	switch status := cfnComputeValue(stack.StackStatus); status {
	case "DELETE_COMPLETE":
		return true, nil
	case "DELETE_FAILED":
		return false, fmt.Errorf("child stack %s reached %s: %s", r.PhysicalID, status, cfnComputeValue(stack.StackStatusReason))
	default:
		return false, nil
	}
}

func (h cfnStack) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	stack, _, err := h.describe(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnStackResult(stack), nil
}

func (h cfnStack) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	stack, _, err := h.describe(ctx, r)
	if cfnStackMissing(err) {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "Stack does not exist in the current scope", StatusCode: 404, Cause: err}
	}
	if err != nil {
		return nil, err
	}
	if cfnComputeValue(stack.StackStatus) == "DELETE_COMPLETE" {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "Stack has been deleted", StatusCode: 404}
	}
	template, err := cfnComputeCall[api.GetTemplateOutput](cfnStackContext(ctx, r), h.commands, "cloudformation", "GetTemplate", map[string]any{"StackName": cfnComputeValue(stack.StackId)})
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"StackId": cfnComputeValue(stack.StackId), "StackName": cfnComputeValue(stack.StackName), "StackStatus": cfnComputeValue(stack.StackStatus), "TemplateBody": cfnComputeValue(template.TemplateBody)}
	parameters := map[string]any{}
	for _, parameter := range stack.Parameters {
		parameters[cfnComputeValue(parameter.ParameterKey)] = cfnComputeValue(parameter.ParameterValue)
	}
	p["Parameters"] = parameters
	capabilities := make([]any, len(stack.Capabilities))
	for i, value := range stack.Capabilities {
		capabilities[i] = string(value)
	}
	p["Capabilities"] = capabilities
	tags := make([]any, len(stack.Tags))
	for i, tag := range stack.Tags {
		tags[i] = map[string]any{"Key": cfnComputeValue(tag.Key), "Value": cfnComputeValue(tag.Value)}
	}
	p["Tags"] = tags
	if stack.RoleARN != nil {
		p["RoleARN"] = cfnComputeValue(stack.RoleARN)
	}
	if stack.DisableRollback != nil {
		p["DisableRollback"] = bool(*stack.DisableRollback)
	}
	if stack.EnableTerminationProtection != nil {
		p["EnableTerminationProtection"] = bool(*stack.EnableTerminationProtection)
	}
	if stack.CreationTime != nil {
		p["CreationTime"] = stack.CreationTime.UTC().Format(time.RFC3339Nano)
	}
	if stack.LastUpdatedTime != nil {
		p["LastUpdateTime"] = stack.LastUpdatedTime.UTC().Format(time.RFC3339Nano)
	}
	if stack.ParentId != nil {
		p["ParentId"] = cfnComputeValue(stack.ParentId)
		p["RootId"] = cfnComputeValue(stack.RootId)
	}
	p["Outputs"] = cfnStackOutputs(stack.Outputs)
	return p, nil
}

func (h cfnStack) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListStacksOutput](cfnStackContext(ctx, r), h.commands, "cloudformation", "ListStacks", input)
		if err != nil {
			return nil, err
		}
		for _, stack := range out.StackSummaries {
			if cfnComputeValue(stack.StackStatus) == "DELETE_COMPLETE" {
				continue
			}
			child := r
			child.PhysicalID = cfnComputeValue(stack.StackId)
			p, err := h.Read(ctx, child)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: child.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return rows, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
