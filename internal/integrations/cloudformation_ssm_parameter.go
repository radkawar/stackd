package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/ssm"
	"stackd/internal/services/cloudformation"
)

// CloudFormationBootstrapHandlers provisions the standard bootstrap dependencies
// through their existing owners, including their ordinary authorization checks.
func CloudFormationBootstrapHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::SSM::Parameter":  cfnSSMParameter{commands},
		"AWS::ECR::Repository": cfnECRRepository{commands},
	}
}

type cfnSSMParameter struct{ commands StepFunctionsCommands }

func (h cfnSSMParameter) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Type", "Value", "Description", "AllowedPattern", "DataType", "Tier", "Policies", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Type", "Value"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "Type", "Value", "Description", "AllowedPattern", "DataType", "Tier", "Policies"); err != nil {
		return err
	}
	if v := cfnComputeString(p, "Type"); v != "String" && v != "StringList" {
		return fmt.Errorf("SSM CloudFormation parameters support String and StringList, not %q", v)
	}
	_, err := cfnSSMTags(p)
	return err
}
func cfnSSMTags(p cloudformation.Properties) (map[string]string, error) {
	out := map[string]string{}
	if p["Tags"] == nil {
		return out, nil
	}
	raw, ok := p["Tags"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("SSM parameter Tags must be a string map")
	}
	for k, v := range raw {
		text, ok := v.(string)
		if !ok || k == "" || strings.HasPrefix(strings.ToLower(k), "aws:") || strings.HasPrefix(k, cfnComputeTagPrefix) {
			return nil, fmt.Errorf("invalid SSM parameter tag %q", k)
		}
		out[k] = text
	}
	return out, nil
}
func (h cfnSSMParameter) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func (h cfnSSMParameter) tags(ctx context.Context, name string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, h.commands, "ssm", "ListTagsForResource", map[string]any{"ResourceType": "Parameter", "ResourceId": name})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, t := range out.TagList {
		tags[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return tags, nil
}
func (h cfnSSMParameter) desiredTags(r cloudformation.ResourceRequest) map[string]string {
	tags := cfnComputeOwnedTags(r)
	own, _ := cfnSSMTags(r.Properties)
	for k, v := range own {
		tags[k] = v
	}
	return tags
}
func (h cfnSSMParameter) result(name string, p cloudformation.Properties) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Type": p["Type"], "Value": p["Value"]}}
}
func (h cfnSSMParameter) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 1011)
	_, err := cfnComputeCall[api.GetParameterOutput](ctx, h.commands, "ssm", "GetParameter", map[string]any{"Name": name})
	if err == nil {
		tags, err := h.tags(ctx, name)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if err := cfnComputeOwnership(r, tags); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		return h.result(name, r.Properties), nil
	}
	if !cfnMessagingMissing(err, "ParameterNotFound") {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "Type", "Value", "Description", "AllowedPattern", "DataType", "Tier", "Policies")
	in["Name"], in["Tags"] = name, cfnComputeTagList(h.desiredTags(r))
	if err := cfnComputeRun(ctx, h.commands, "ssm", "PutParameter", in); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(name, r.Properties), nil
}
func (h cfnSSMParameter) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	tags, err := h.tags(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if !r.CloudControl {
		if err := cfnComputeOwnership(r, tags); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	in := cfnComputeCopy(r.Properties, "Type", "Value", "Description", "AllowedPattern", "DataType", "Tier", "Policies")
	for _, k := range []string{"Description", "AllowedPattern"} {
		if _, ok := in[k]; !ok {
			in[k] = ""
		}
	}
	if in["Policies"] == nil && r.Previous["Policies"] != nil {
		in["Policies"] = "[]"
	}
	in["Name"], in["Overwrite"] = r.PhysicalID, true
	result := h.result(r.PhysicalID, r.Properties)
	if err := cfnComputeRun(ctx, h.commands, "ssm", "PutParameter", in); err != nil {
		return result, err
	}
	desired := cfnResourceMutationTags(r, tags, h.desiredTags(r))
	if removed := cfnComputeRemovedTags(tags, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, h.commands, "ssm", "RemoveTagsFromResource", map[string]any{"ResourceType": "Parameter", "ResourceId": r.PhysicalID, "TagKeys": removed}); err != nil {
			return result, err
		}
	}
	if len(desired) == 0 {
		return result, nil
	}
	return result, cfnComputeRun(ctx, h.commands, "ssm", "AddTagsToResource", map[string]any{"ResourceType": "Parameter", "ResourceId": r.PhysicalID, "Tags": cfnComputeTagList(desired)})
}
func (h cfnSSMParameter) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeName(r, "Name", 1011)
	tags, err := h.tags(ctx, name)
	if cfnMessagingMissing(err, "ParameterNotFound", "InvalidResourceId") {
		return nil
	}
	if err != nil {
		return err
	}
	if !r.CloudControl {
		if err := cfnComputeOwnership(r, tags); err != nil {
			return err
		}
	}
	err = cfnComputeRun(ctx, h.commands, "ssm", "DeleteParameter", map[string]any{"Name": name})
	if cfnMessagingMissing(err, "ParameterNotFound") {
		return nil
	}
	return err
}
func (h cfnSSMParameter) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := cfnComputeCall[api.GetParameterOutput](ctx, h.commands, "ssm", "GetParameter", map[string]any{"Name": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	if out.Parameter == nil {
		return nil, fmt.Errorf("SSM returned no parameter")
	}
	if cfnComputeValue(out.Parameter.Type) == "SecureString" {
		return nil, fmt.Errorf("SecureString is not a CloudFormation parameter resource")
	}
	p := cloudformation.Properties{"Name": r.PhysicalID, "Type": cfnComputeValue(out.Parameter.Type), "Value": cfnComputeValue(out.Parameter.Value), "DataType": cfnComputeValue(out.Parameter.DataType)}
	meta, err := cfnComputeCall[api.DescribeParametersOutput](ctx, h.commands, "ssm", "DescribeParameters", map[string]any{"ParameterFilters": []any{map[string]any{"Key": "Name", "Option": "Equals", "Values": []string{r.PhysicalID}}}})
	if err != nil {
		return nil, err
	}
	for _, row := range meta.Parameters {
		if cfnComputeValue(row.Name) != r.PhysicalID {
			continue
		}
		if row.Description != nil {
			p["Description"] = cfnComputeValue(row.Description)
		}
		if row.AllowedPattern != nil {
			p["AllowedPattern"] = cfnComputeValue(row.AllowedPattern)
		}
		if row.Tier != nil {
			p["Tier"] = cfnComputeValue(row.Tier)
		}
		if len(row.Policies) > 0 {
			policies := []json.RawMessage{}
			for _, policy := range row.Policies {
				policies = append(policies, json.RawMessage(cfnComputeValue(policy.PolicyText)))
			}
			b, err := json.Marshal(policies)
			if err != nil {
				return nil, err
			}
			p["Policies"] = string(b)
		}
	}
	tags, err := h.tags(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	public := map[string]any{}
	for k, v := range tags {
		if !strings.HasPrefix(k, cfnComputeTagPrefix) && !strings.HasPrefix(k, "aws:") {
			public[k] = v
		}
	}
	p["Tags"] = public
	return p, nil
}
func (h cfnSSMParameter) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeParametersOutput](ctx, h.commands, "ssm", "DescribeParameters", in)
		if err != nil {
			return nil, err
		}
		for _, row := range out.Parameters {
			if cfnComputeValue(row.Type) == "SecureString" {
				continue
			}
			name := cfnComputeValue(row.Name)
			result = append(result, cloudformation.ResourceDescription{Identifier: name, Properties: cloudformation.Properties{"Name": name}})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return result, nil
		}
		in["NextToken"] = *out.NextToken
	}
}

// CloudFormationParameterSource resolves template parameter types, not resources.
type CloudFormationParameterSource struct{ Commands StepFunctionsCommands }

func (a CloudFormationParameterSource) ResolveParameter(ctx context.Context, name string) (string, error) {
	out, err := cfnComputeCall[api.GetParameterOutput](ctx, a.Commands, "ssm", "GetParameter", map[string]any{"Name": name})
	if err != nil {
		return "", err
	}
	if out.Parameter == nil {
		return "", fmt.Errorf("SSM returned no parameter")
	}
	if cfnComputeValue(out.Parameter.Type) == "SecureString" {
		return "", fmt.Errorf("SecureString template parameters are unsupported")
	}
	return cfnComputeValue(out.Parameter.Value), nil
}
