package integrations

import (
	"context"
	"errors"
	"fmt"
	api "stackd/internal/awsapi/xray"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/xray"
	"strings"
)

func cfnXRayContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return xray.WithCloudFormationOwner(ctx, cfnLogsMarker(r), create)
}
func cfnXRayDesiredTags(r cloudformation.ResourceRequest) map[string]string {
	return cfnResourceTags(r)
}
func cfnXRayTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsForResourceResponse](ctx, c, "xray", "ListTagsForResource", map[string]any{"ResourceARN": arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, t := range out.Tags {
		tags[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return tags, nil
}
func cfnXRaySyncTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string) error {
	ctx = cfnXRayContext(ctx, r, false)
	current, err := cfnXRayTags(ctx, c, arn)
	if err != nil {
		return err
	}
	desired := cfnXRayDesiredTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "xray", "UntagResource", map[string]any{"ResourceARN": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) > 0 {
		return cfnComputeRun(ctx, c, "xray", "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(desired)})
	}
	return nil
}
func cfnXRayAbsent(err error) error {
	var wire *awswire.Error
	if errors.As(err, &wire) && wire.Code == "InvalidRequestException" && (wire.Message == "Group not found" || wire.Message == "Sampling rule does not exist" || strings.HasPrefix(wire.Message, "Resource policy does not exist:")) {
		return nil
	}
	return cfnComputeAbsent(err)
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-xray-group.html
type cfnXRayGroup struct{ commands StepFunctionsCommands }

func (h cfnXRayGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "GroupName", "FilterExpression", "InsightsConfiguration", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "GroupName", "FilterExpression"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnXRayGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "GroupName"), h.Validate(b)
}
func cfnXRayGroupResult(group *api.Group) cloudformation.ResourceResult {
	arn := cfnComputeValue(group.GroupARN)
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"GroupARN": arn}}
}
func (h cfnXRayGroup) admit(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "GroupName", "FilterExpression", "InsightsConfiguration")
	input["Tags"] = cfnComputeTagList(cfnXRayDesiredTags(r))
	out, err := cfnComputeCall[api.CreateGroupResult](ctx, h.commands, "xray", "CreateGroup", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnXRayGroupResult(out.Group), nil
}
func (h cfnXRayGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.admit(xray.WithCloudFormationRecovery(ctx, cfnLogsMarker(r)), r)
}
func (h cfnXRayGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnXRayContext(ctx, r, true)
	result, err := h.admit(ctx, r)
	if err != nil {
		recovered, recoveryErr := h.RecoverCreation(ctx, r)
		if recoveryErr == nil {
			return recovered, err
		}
		if !cfnComputeMissing(recoveryErr) {
			return cloudformation.ResourceResult{}, errors.Join(err, recoveryErr)
		}
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = result.PhysicalID
	_, err = h.Update(ctx, r)
	return result, err
}
func (h cfnXRayGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "FilterExpression", "InsightsConfiguration")
	if strings.HasPrefix(r.PhysicalID, "arn:") {
		if err := cfnMessagingScopeARN(r, r.PhysicalID, "xray"); err != nil {
			return cloudformation.ResourceResult{}, err
		}
		input["GroupARN"] = r.PhysicalID
	} else {
		input["GroupName"] = r.PhysicalID
	}
	out, err := cfnComputeCall[api.UpdateGroupResult](cfnXRayContext(ctx, r, false), h.commands, "xray", "UpdateGroup", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnXRayGroupResult(out.Group)
	return result, cfnXRaySyncTags(ctx, h.commands, r, cfnComputeValue(out.Group.GroupARN))
}
func (h cfnXRayGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	input := map[string]any{}
	if strings.HasPrefix(r.PhysicalID, "arn:") {
		if err := cfnMessagingScopeARN(r, r.PhysicalID, "xray"); err != nil {
			return err
		}
		input["GroupARN"] = r.PhysicalID
	} else {
		input["GroupName"] = cfnObservabilityName(r, "GroupName", 32)
	}
	return cfnXRayAbsent(cfnComputeRun(cfnXRayContext(ctx, r, false), h.commands, "xray", "DeleteGroup", input))
}
func (h cfnXRayGroup) model(ctx context.Context, group *api.Group) (cloudformation.Properties, error) {
	p := cfnObservabilityModel(group)
	tags, err := cfnXRayTags(ctx, h.commands, cfnComputeValue(group.GroupARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnXRayGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	input := map[string]any{}
	if strings.HasPrefix(r.PhysicalID, "arn:") {
		if err := cfnMessagingScopeARN(r, r.PhysicalID, "xray"); err != nil {
			return nil, err
		}
		input["GroupARN"] = r.PhysicalID
	} else {
		input["GroupName"] = r.PhysicalID
	}
	out, err := cfnComputeCall[api.GetGroupResult](ctx, h.commands, "xray", "GetGroup", input)
	if err != nil {
		if cfnXRayAbsent(err) == nil {
			return nil, cfnObservabilityNotFound()
		}
		return nil, err
	}
	return h.model(ctx, out.Group)
}
func (h cfnXRayGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.GetGroupsResult](ctx, h.commands, "xray", "GetGroups", input)
		if err != nil {
			return nil, err
		}
		for _, group := range out.Groups {
			r.PhysicalID = cfnComputeValue(group.GroupARN)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return result, nil
		}
		input["NextToken"] = string(*out.NextToken)
	}
}

// The native sampling owner retains reservoir/target/statistic state on updates:
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-xray-samplingrule.html
type cfnXRaySamplingRule struct{ commands StepFunctionsCommands }

func (h cfnXRaySamplingRule) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "SamplingRule", "Tags"); err != nil {
		return err
	}
	rule, ok := cfnComputeObject(p["SamplingRule"])
	if !ok {
		return fmt.Errorf("SamplingRule must be an object")
	}
	if err := cfnComputeProperties(rule, "RuleName", "RuleARN", "Version", "Priority", "FixedRate", "ReservoirSize", "Host", "HTTPMethod", "ResourceARN", "ServiceName", "ServiceType", "URLPath", "Attributes", "SamplingRateBoost"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnXRaySamplingRule) Replacement(a, b cloudformation.Properties) (bool, error) {
	old, _ := cfnComputeObject(a["SamplingRule"])
	next, _ := cfnComputeObject(b["SamplingRule"])
	if cfnComputeChanged(old, next, "Version") && old["Version"] != nil && next["Version"] != nil {
		return false, fmt.Errorf("SamplingRule.Version cannot be updated")
	}
	return cfnComputeChanged(old, next, "RuleName", "RuleARN"), h.Validate(b)
}
func cfnXRaySamplingResult(rule *api.SamplingRule) cloudformation.ResourceResult {
	arn := cfnComputeValue(rule.RuleARN)
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"RuleARN": arn}}
}
func (h cfnXRaySamplingRule) find(ctx context.Context, id string) (*api.SamplingRule, error) {
	out, err := cfnComputeCall[api.GetSamplingRulesResult](ctx, h.commands, "xray", "GetSamplingRules", map[string]any{})
	if err != nil {
		return nil, err
	}
	for _, row := range out.SamplingRuleRecords {
		if row.SamplingRule != nil && (cfnComputeValue(row.SamplingRule.RuleName) == id || cfnComputeValue(row.SamplingRule.RuleARN) == id) {
			return row.SamplingRule, nil
		}
	}
	return nil, cfnObservabilityNotFound()
}
func (h cfnXRaySamplingRule) admit(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	rule, _ := cfnComputeObject(r.Properties["SamplingRule"])
	input := cfnComputeCopy(rule, "RuleName", "Version", "Priority", "FixedRate", "ReservoirSize", "Host", "HTTPMethod", "ResourceARN", "ServiceName", "ServiceType", "URLPath", "Attributes", "SamplingRateBoost")
	if input["RuleName"] == nil {
		nested := r
		nested.Properties = rule
		input["RuleName"] = cfnComputeName(nested, "RuleName", 32)
	}
	if input["Version"] == nil {
		input["Version"] = 1
	}
	out, err := cfnComputeCall[api.CreateSamplingRuleResult](ctx, h.commands, "xray", "CreateSamplingRule", map[string]any{"SamplingRule": input, "Tags": cfnComputeTagList(cfnXRayDesiredTags(r))})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnXRaySamplingResult(out.SamplingRuleRecord.SamplingRule), nil
}
func (h cfnXRaySamplingRule) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.admit(xray.WithCloudFormationRecovery(ctx, cfnLogsMarker(r)), r)
}
func (h cfnXRaySamplingRule) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnXRayContext(ctx, r, true)
	result, err := h.admit(ctx, r)
	if err != nil {
		recovered, recoveryErr := h.RecoverCreation(ctx, r)
		if recoveryErr == nil {
			return recovered, err
		}
		if !cfnComputeMissing(recoveryErr) {
			return cloudformation.ResourceResult{}, errors.Join(err, recoveryErr)
		}
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = result.PhysicalID
	_, err = h.Update(ctx, r)
	return result, err
}
func (h cfnXRaySamplingRule) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	rule, _ := cfnComputeObject(r.Properties["SamplingRule"])
	input := cfnComputeCopy(rule, "Priority", "FixedRate", "ReservoirSize", "Host", "HTTPMethod", "ResourceARN", "ServiceName", "ServiceType", "URLPath", "Attributes", "SamplingRateBoost")
	if input["Attributes"] == nil {
		input["Attributes"] = map[string]string{}
	}
	if strings.HasPrefix(r.PhysicalID, "arn:") {
		if err := cfnMessagingScopeARN(r, r.PhysicalID, "xray"); err != nil {
			return cloudformation.ResourceResult{}, err
		}
		input["RuleARN"] = r.PhysicalID
	} else {
		input["RuleName"] = r.PhysicalID
	}
	out, err := cfnComputeCall[api.UpdateSamplingRuleResult](cfnXRayContext(ctx, r, false), h.commands, "xray", "UpdateSamplingRule", map[string]any{"SamplingRuleUpdate": input})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnXRaySamplingResult(out.SamplingRuleRecord.SamplingRule)
	return result, cfnXRaySyncTags(ctx, h.commands, r, cfnComputeValue(out.SamplingRuleRecord.SamplingRule.RuleARN))
}
func (h cfnXRaySamplingRule) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	input := map[string]any{}
	id := r.PhysicalID
	if id == "" {
		rule, _ := cfnComputeObject(r.Properties["SamplingRule"])
		nested := r
		nested.Properties = rule
		id = cfnComputeName(nested, "RuleName", 32)
	}
	if strings.HasPrefix(id, "arn:") {
		if err := cfnMessagingScopeARN(r, id, "xray"); err != nil {
			return err
		}
		input["RuleARN"] = id
	} else {
		input["RuleName"] = id
	}
	return cfnXRayAbsent(cfnComputeRun(cfnXRayContext(ctx, r, false), h.commands, "xray", "DeleteSamplingRule", input))
}
func (h cfnXRaySamplingRule) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	if strings.HasPrefix(r.PhysicalID, "arn:") {
		if err := cfnMessagingScopeARN(r, r.PhysicalID, "xray"); err != nil {
			return nil, err
		}
	}
	rule, err := h.find(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	tags, err := cfnXRayTags(ctx, h.commands, cfnComputeValue(rule.RuleARN))
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"SamplingRule": cfnObservabilityModel(rule), "RuleARN": cfnComputeValue(rule.RuleARN), "Tags": cfnResourcePublicTags(tags)}
	return p, nil
}
func (h cfnXRaySamplingRule) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	out, err := cfnComputeCall[api.GetSamplingRulesResult](ctx, h.commands, "xray", "GetSamplingRules", map[string]any{})
	if err != nil {
		return nil, err
	}
	var result []cloudformation.ResourceDescription
	for _, row := range out.SamplingRuleRecords {
		r.PhysicalID = cfnComputeValue(row.SamplingRule.RuleARN)
		p, err := h.Read(ctx, r)
		if err != nil {
			return nil, err
		}
		result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
	}
	return result, nil
}

// Resource policy revisions, principal binding and lockout prevention stay in
// the X-Ray owner rather than a second CFN policy store.
type cfnXRayResourcePolicy struct{ commands StepFunctionsCommands }

func (h cfnXRayResourcePolicy) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "PolicyName", "PolicyDocument", "BypassPolicyLockoutCheck"); err != nil {
		return err
	}
	return cfnComputeRequired(p, "PolicyName", "PolicyDocument")
}
func (h cfnXRayResourcePolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "PolicyName"), h.Validate(b)
}
func (h cfnXRayResourcePolicy) write(ctx context.Context, r cloudformation.ResourceRequest, create bool) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnObservabilityName(r, "PolicyName", 128)
	document, err := cfnComputeDocument(r.Properties["PolicyDocument"])
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	input := map[string]any{"PolicyName": name, "PolicyDocument": document}
	if value, ok := r.Properties["BypassPolicyLockoutCheck"]; ok {
		input["BypassPolicyLockoutCheck"] = value
	}
	return result, cfnComputeRun(cfnXRayContext(ctx, r, create), h.commands, "xray", "PutResourcePolicy", input)
}
func (h cfnXRayResourcePolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, true)
}
func (h cfnXRayResourcePolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, false)
}
func (h cfnXRayResourcePolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return cfnXRayAbsent(cfnComputeRun(cfnXRayContext(ctx, r, false), h.commands, "xray", "DeleteResourcePolicy", map[string]any{"PolicyName": cfnObservabilityName(r, "PolicyName", 128)}))
}
func (h cfnXRayResourcePolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	out, err := cfnComputeCall[api.ListResourcePoliciesResult](ctx, h.commands, "xray", "ListResourcePolicies", map[string]any{})
	if err != nil {
		return nil, err
	}
	var result []cloudformation.ResourceDescription
	for _, policy := range out.ResourcePolicies {
		p := cloudformation.Properties{"PolicyName": cfnComputeValue(policy.PolicyName), "PolicyDocument": cfnComputeValue(policy.PolicyDocument)}
		result = append(result, cloudformation.ResourceDescription{Identifier: cfnComputeValue(policy.PolicyName), Properties: p})
	}
	return result, nil
}
func (h cfnXRayResourcePolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := h.List(ctx, r)
	if err != nil {
		return nil, err
	}
	for _, p := range out {
		if p.Identifier == r.PhysicalID {
			return p.Properties, nil
		}
	}
	return nil, cfnObservabilityNotFound()
}
