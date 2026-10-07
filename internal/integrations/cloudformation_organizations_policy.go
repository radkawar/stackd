package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	api "stackd/internal/awsapi/organizations"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-organizations-policy.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-organizations-resourcepolicy.html
type cfnOrganizationPolicy struct{ commands StepFunctionsCommands }

func (h cfnOrganizationPolicy) Validate(p cloudformation.Properties) error {
	if e := cfnOrganizationsValidate(p, []string{"Name", "Type", "Content"}, "Name", "Type", "Content", "Description", "TargetIds", "Tags"); e != nil {
		return e
	}
	if e := cfnComputeStrings(p, "Name", "Type", "Description"); e != nil {
		return e
	}
	if _, e := cfnComputeDocument(p["Content"]); e != nil {
		return e
	}
	_, e := cfnComputeStringList(p, "TargetIds")
	return e
}
func (h cfnOrganizationPolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Type"), h.Validate(b)
}
func (h cfnOrganizationPolicy) targets(ctx context.Context, id string) ([]string, error) {
	var rows []string
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListTargetsForPolicyOutput](ctx, h.commands, "organizations", "ListTargetsForPolicy", map[string]any{"PolicyId": id, "NextToken": next})
		if e != nil {
			return nil, e
		}
		for _, t := range out.Targets {
			rows = append(rows, cfnComputeValue(t.TargetId))
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
	}
}
func (h cfnOrganizationPolicy) attach(ctx context.Context, r cloudformation.ResourceRequest) error {
	current, e := h.targets(ctx, r.PhysicalID)
	if e != nil {
		return e
	}
	desired, e := cfnComputeStringList(r.Properties, "TargetIds")
	if e != nil {
		return e
	}
	for _, id := range current {
		if !slices.Contains(desired, id) {
			if e := cfnComputeRun(ctx, h.commands, "organizations", "DetachPolicy", map[string]any{"PolicyId": r.PhysicalID, "TargetId": id}); e != nil {
				return e
			}
		}
	}
	for _, id := range desired {
		if !slices.Contains(current, id) {
			if e := cfnComputeRun(ctx, h.commands, "organizations", "AttachPolicy", map[string]any{"PolicyId": r.PhysicalID, "TargetId": id}); e != nil {
				return e
			}
		}
	}
	return nil
}

// Policies carry a private incarnation claim. Native same-name policies and
// public tags are never adopted; Cloud Control direct mutations remain IAM-only.
func (h cfnOrganizationPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	content, e := cfnComputeDocument(r.Properties["Content"])
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	input := cfnComputeCopy(r.Properties, "Name", "Type")
	input["Description"] = cfnComputeDefault(r.Properties, "Description", "")
	input["Content"] = content
	input["Tags"] = cfnComputeTagList(cfnOrgIdentityTags(r))
	owned := cfnOrgIdentityClaim(ctx, r)
	out, e := cfnOrgIdentityCall[api.CreatePolicyOutput](owned, h.commands, "organizations", "CreatePolicy", input)
	if cfnMessagingMissing(e, "DuplicatePolicyException") {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, e)
	}
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	r.PhysicalID = cfnComputeValue(out.Policy.PolicySummary.Id)
	e = h.attach(owned, r)
	result, re := cfnOrgIdentityRefreshResult(ctx, h, r)
	if e != nil {
		return result, e
	}
	return result, re
}

// RecoverCreation observes only the policy committed under this exact incarnation.
func (h cfnOrganizationPolicy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	rows, e := h.summaries(cfnOrgIdentityClaim(ctx, r), cfnComputeString(r.Properties, "Type"))
	if e != nil {
		return cloudformation.ResourceResult{}, cfnOrgIdentityUnobserved(e)
	}
	if len(rows) == 0 {
		return cloudformation.ResourceResult{}, cfnOrgIdentityNotFound("policy was not created by this incarnation")
	}
	r.PhysicalID = cfnComputeValue(rows[0].Id)
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}
func (h cfnOrganizationPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	content, e := cfnComputeDocument(r.Properties["Content"])
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	owned := cfnOrgIdentityContext(ctx, r)
	if e = cfnComputeRun(owned, h.commands, "organizations", "UpdatePolicy", map[string]any{"PolicyId": r.PhysicalID, "Name": r.Properties["Name"], "Description": cfnComputeDefault(r.Properties, "Description", ""), "Content": content}); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	e = h.attach(owned, r)
	if e == nil {
		var tags map[string]string
		if tags, e = cfnOrganizationsTags(owned, h.commands, r.PhysicalID); e == nil {
			e = cfnOrganizationsUpdateTags(owned, h.commands, r, r.PhysicalID, tags, cfnOrgIdentityTags(r))
		}
	}
	result, re := cfnOrgIdentityRefreshResult(ctx, h, r)
	if e != nil {
		return result, e
	}
	return result, re
}

// A foreign claim hides the targets observer, but DeletePolicy itself is fenced.
func (h cfnOrganizationPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	owned := cfnOrgIdentityContext(ctx, r)
	r.Properties = cloudformation.Properties{}
	if e := h.attach(owned, r); e != nil && !cfnOrganizationsMissing(e) {
		return e
	}
	e := cfnComputeRun(owned, h.commands, "organizations", "DeletePolicy", map[string]any{"PolicyId": r.PhysicalID})
	if cfnOrganizationsMissing(e) {
		return nil
	}
	return e
}
func (h cfnOrganizationPolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, e := cfnOrgIdentityCall[api.DescribePolicyOutput](ctx, h.commands, "organizations", "DescribePolicy", map[string]any{"PolicyId": r.PhysicalID})
	if e != nil {
		return nil, e
	}
	p := out.Policy
	tags, e := cfnOrganizationsTags(ctx, h.commands, r.PhysicalID)
	if e != nil {
		return nil, e
	}
	targets, e := h.targets(ctx, r.PhysicalID)
	if e != nil {
		return nil, e
	}
	var content any
	if e = json.Unmarshal([]byte(cfnComputeValue(p.Content)), &content); e != nil {
		return nil, e
	}
	v := p.PolicySummary
	return cloudformation.Properties{"Id": r.PhysicalID, "Arn": cfnComputeValue(v.Arn), "Name": cfnComputeValue(v.Name), "Type": cfnComputeValue(v.Type), "Description": cfnComputeValue(v.Description), "AwsManaged": v.AwsManaged, "Content": content, "TargetIds": targets, "Tags": cfnResourcePublicTags(tags)}, nil
}
func (h cfnOrganizationPolicy) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, e := h.Read(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnOrgIdentityResult(r.PhysicalID, p), nil
}
func (h cfnOrganizationPolicy) summaries(ctx context.Context, kind string) ([]api.PolicySummary, error) {
	var rows []api.PolicySummary
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListPoliciesOutput](ctx, h.commands, "organizations", "ListPolicies", map[string]any{"Filter": kind, "NextToken": next})
		if e != nil {
			return nil, e
		}
		rows = append(rows, out.Policies...)
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
	}
}
func (h cfnOrganizationPolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	kinds := []string{cfnComputeString(r.Properties, "Type")}
	if kinds[0] == "" {
		out, e := cfnOrgIdentityCall[api.DescribeOrganizationOutput](ctx, h.commands, "organizations", "DescribeOrganization", map[string]any{})
		if e != nil {
			return nil, e
		}
		kinds = nil
		for _, v := range out.Organization.AvailablePolicyTypes {
			kinds = append(kinds, cfnComputeValue(v.Type))
		}
	}
	var rows []cloudformation.ResourceDescription
	for _, kind := range kinds {
		summaries, e := h.summaries(ctx, kind)
		if e != nil {
			return nil, e
		}
		for _, v := range summaries {
			if v.AwsManaged != nil && bool(*v.AwsManaged) {
				continue
			}
			r.PhysicalID = cfnComputeValue(v.Id)
			p, e := h.Read(ctx, r)
			if e != nil {
				return nil, e
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
	}
	return rows, nil
}

type cfnOrganizationResourcePolicy struct{ commands StepFunctionsCommands }

func (h cfnOrganizationResourcePolicy) Validate(p cloudformation.Properties) error {
	if e := cfnOrganizationsValidate(p, []string{"Content"}, "Content", "Tags"); e != nil {
		return e
	}
	_, e := cfnComputeDocument(p["Content"])
	return e
}
func (h cfnOrganizationResourcePolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}

// The singleton delegation policy carries a private incarnation claim. An
// existing foreign policy is never adopted, whatever its public tags say.
func (h cfnOrganizationResourcePolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	owned := cfnOrgIdentityClaim(ctx, r)
	if _, e := cfnOrgIdentityCall[api.DescribeResourcePolicyOutput](ctx, h.commands, "organizations", "DescribeResourcePolicy", map[string]any{}); e == nil {
		mine, e := cfnOrgIdentityCall[api.DescribeResourcePolicyOutput](owned, h.commands, "organizations", "DescribeResourcePolicy", map[string]any{})
		if cfnOrganizationsMissing(e) {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("the organization already has a resource policy owned by another incarnation"))
		}
		if e != nil {
			return cloudformation.ResourceResult{}, e
		}
		r.PhysicalID = cfnComputeValue(mine.ResourcePolicy.ResourcePolicySummary.Id)
		return h.apply(ctx, owned, r)
	} else if !cfnOrganizationsMissing(e) {
		return cloudformation.ResourceResult{}, e
	}
	content, e := cfnComputeDocument(r.Properties["Content"])
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	out, e := cfnOrgIdentityCall[api.PutResourcePolicyOutput](owned, h.commands, "organizations", "PutResourcePolicy", map[string]any{"Content": content, "Tags": cfnComputeTagList(cfnOrgIdentityTags(r))})
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	r.PhysicalID = cfnComputeValue(out.ResourcePolicy.ResourcePolicySummary.Id)
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}

// RecoverCreation observes only the policy committed under this exact incarnation.
func (h cfnOrganizationResourcePolicy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	out, e := cfnOrgIdentityCall[api.DescribeResourcePolicyOutput](cfnOrgIdentityClaim(ctx, r), h.commands, "organizations", "DescribeResourcePolicy", map[string]any{})
	if cfnMessagingMissing(e, "ResourcePolicyNotFoundException") {
		return cloudformation.ResourceResult{}, cfnOrgIdentityNotFound("resource policy was not created by this incarnation")
	}
	if e != nil {
		return cloudformation.ResourceResult{}, cfnOrgIdentityUnobserved(e)
	}
	r.PhysicalID = cfnComputeValue(out.ResourcePolicy.ResourcePolicySummary.Id)
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}
func (h cfnOrganizationResourcePolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return h.apply(ctx, cfnOrgIdentityContext(ctx, r), r)
}

// apply updates the observed incarnation only; PutResourcePolicy never recreates it.
func (h cfnOrganizationResourcePolicy) apply(ctx, owned context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	content, e := cfnComputeDocument(r.Properties["Content"])
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	current, e := cfnOrgIdentityCall[api.DescribeResourcePolicyOutput](owned, h.commands, "organizations", "DescribeResourcePolicy", map[string]any{})
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	if cfnComputeValue(current.ResourcePolicy.ResourcePolicySummary.Id) != r.PhysicalID {
		return cloudformation.ResourceResult{}, cfnOrgIdentityNotFound("Organizations resource policy identity changed")
	}
	if e = cfnComputeRun(owned, h.commands, "organizations", "PutResourcePolicy", map[string]any{"Content": content}); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	tags, e := cfnOrganizationsTags(owned, h.commands, r.PhysicalID)
	if e == nil {
		e = cfnOrganizationsUpdateTags(owned, h.commands, r, r.PhysicalID, tags, cfnOrgIdentityTags(r))
	}
	result, re := cfnOrgIdentityRefreshResult(ctx, h, r)
	if e != nil {
		return result, e
	}
	return result, re
}

// A replaced singleton is another incarnation; DeleteResourcePolicy itself is fenced.
func (h cfnOrganizationResourcePolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	out, e := cfnOrgIdentityCall[api.DescribeResourcePolicyOutput](ctx, h.commands, "organizations", "DescribeResourcePolicy", map[string]any{})
	if cfnOrganizationsMissing(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if cfnComputeValue(out.ResourcePolicy.ResourcePolicySummary.Id) != r.PhysicalID {
		return nil
	}
	e = cfnComputeRun(cfnOrgIdentityContext(ctx, r), h.commands, "organizations", "DeleteResourcePolicy", map[string]any{})
	if cfnOrganizationsMissing(e) {
		return nil
	}
	return e
}
func (h cfnOrganizationResourcePolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, e := cfnOrgIdentityCall[api.DescribeResourcePolicyOutput](ctx, h.commands, "organizations", "DescribeResourcePolicy", map[string]any{})
	if e != nil {
		return nil, e
	}
	v := out.ResourcePolicy
	id := cfnComputeValue(v.ResourcePolicySummary.Id)
	if r.PhysicalID != "" && r.PhysicalID != id {
		return nil, cfnOrgIdentityNotFound("Organizations resource policy identity changed")
	}
	tags, e := cfnOrganizationsTags(ctx, h.commands, id)
	if e != nil {
		return nil, e
	}
	var content any
	if e = json.Unmarshal([]byte(cfnComputeValue(v.Content)), &content); e != nil {
		return nil, e
	}
	return cloudformation.Properties{"Id": id, "Arn": cfnComputeValue(v.ResourcePolicySummary.Arn), "Content": content, "Tags": cfnResourcePublicTags(tags)}, nil
}
func (h cfnOrganizationResourcePolicy) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, e := h.Read(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnOrgIdentityResult(cfnComputeString(p, "Id"), p), nil
}
func (h cfnOrganizationResourcePolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	p, e := h.Read(ctx, r)
	if cfnOrganizationsMissing(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	return []cloudformation.ResourceDescription{{Identifier: cfnComputeString(p, "Id"), Properties: p}}, nil
}
