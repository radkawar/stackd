package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ssm"
	"stackd/internal/services/ssmdocuments"
)

// cfnSSMClaim is the private native provenance of one exact resource
// incarnation. The SSM owners store it on the parameter or document row in
// the transaction that creates it; it is never a tag.
func cfnSSMClaim(r cloudformation.ResourceRequest) string {
	claim, _ := json.Marshal([]string{r.Type, r.StackID, r.LogicalID, r.Token})
	return string(claim)
}

// cfnSSMParameterContext binds this incarnation's parameter claim. Cloud
// Control creates claim their new parameter; other Cloud Control operations
// act on an existing parameter under current IAM alone.
func cfnSSMParameterContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return ssm.WithCloudFormationParameterOwner(ctx, cfnSSMClaim(r))
}

// cfnSSMDocumentContext binds this incarnation's document claim with the same
// Cloud Control rule as parameters.
func cfnSSMDocumentContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return ssmdocuments.WithCloudFormationDocumentOwner(ctx, cfnSSMClaim(r))
}

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
		if !ok || k == "" || strings.HasPrefix(strings.ToLower(k), "aws:") {
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

// desiredTags are the parameter's customer tags: stack tags and resource
// tags. They carry no ownership; only the private claim
// fences parameter commands and recovery.
func (h cfnSSMParameter) desiredTags(r cloudformation.ResourceRequest) map[string]string {
	tags := cfnResourceTags(r)
	own, _ := cfnSSMTags(r.Properties)
	if len(own) != 0 && tags == nil {
		return own
	}
	for k, v := range own {
		tags[k] = v
	}
	return tags
}
func (h cfnSSMParameter) result(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	arn := "arn:" + r.Scope.Partition + ":ssm:" + r.Scope.Region + ":" + r.Scope.Account + ":parameter"
	if !strings.HasPrefix(name, "/") {
		arn += "/"
	}
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Type": r.Properties["Type"], "Value": r.Properties["Value"], "Arn": arn + name}}
}
func (h cfnSSMParameter) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 1011)
	ctx = cfnSSMParameterContext(ctx, r, true)
	in := cfnComputeCopy(r.Properties, "Type", "Value", "Description", "AllowedPattern", "DataType", "Tier", "Policies")
	in["Name"], in["Tags"] = name, cfnComputeTagList(h.desiredTags(r))
	// The owner admits a new parameter with this claim, or returns the one this
	// exact incarnation already committed; any other parameter is rejected.
	if err := cfnComputeRun(ctx, h.commands, "ssm", "PutParameter", in); err != nil {
		if cfnMessagingMissing(err, "ParameterAlreadyExists") {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		// A failed reply is not evidence that admission did not occur.
		if recovered, recoveryErr := h.RecoverCreation(ctx, r); recoveryErr == nil {
			return recovered, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return h.result(r, name), nil
}

// RecoverCreation observes only the parameter whose private claim is this exact
// incarnation. A same-name parameter with copied tags is foreign.
func (h cfnSSMParameter) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnComputeName(r, "Name", 1011)
	if _, err := cfnComputeCall[api.GetParameterOutput](cfnSSMParameterContext(ctx, r, true), h.commands, "ssm", "GetParameter", map[string]any{"Name": name}); err != nil {
		return cloudformation.ResourceResult{}, cfnStorageMissing(err, "ParameterNotFound")
	}
	return h.result(r, name), nil
}
func (h cfnSSMParameter) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnSSMParameterContext(ctx, r, false)
	tags, err := h.tags(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
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
	result := h.result(r, r.PhysicalID)
	if err := cfnComputeRun(ctx, h.commands, "ssm", "PutParameter", in); err != nil {
		return result, err
	}
	desired := h.desiredTags(r)
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
	err := cfnComputeRun(cfnSSMParameterContext(ctx, r, false), h.commands, "ssm", "DeleteParameter", map[string]any{"Name": name})
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
		if !strings.HasPrefix(k, "aws:") {
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

// CloudFormationParameterSource reads ordinary parameters through their SSM owner.
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

func (a CloudFormationParameterSource) ResolveParameterVersion(ctx context.Context, name string) (string, int64, error) {
	out, err := cfnComputeCall[api.GetParametersOutput](ctx, a.Commands, "ssm", "GetParameters", map[string]any{"Names": []string{name}})
	if err != nil {
		return "", 0, err
	}
	if len(out.Parameters) != 1 {
		code := "ParameterNotFound"
		if strings.Contains(name, ":") {
			code = "ParameterVersionNotFound"
		}
		return "", 0, &awswire.Error{Code: code, Message: "The referenced SSM parameter or version was not found.", StatusCode: 400}
	}
	parameter := out.Parameters[0]
	if cfnComputeValue(parameter.Type) != "String" {
		return "", 0, &awswire.Error{Code: "ValidationError", Message: "Plain SSM dynamic references require a String parameter; SecureString is unsupported.", StatusCode: 400}
	}
	var version int64
	if parameter.Version != nil {
		version = int64(*parameter.Version)
	}
	return cfnComputeValue(parameter.Value), version, nil
}
