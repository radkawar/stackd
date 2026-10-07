package integrations

import (
	"context"
	api "stackd/internal/awsapi/ssoadmin"
	"stackd/internal/services/cloudformation"
)

func cfnSSOTags(ctx context.Context, c StepFunctionsCommands, instance, arn string) (map[string]string, error) {
	tags := map[string]string{}
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListTagsForResourceOutput](ctx, c, "ssoadmin", "ListTagsForResource", map[string]any{"InstanceArn": instance, "ResourceArn": arn, "NextToken": next})
		if e != nil {
			return nil, e
		}
		for _, v := range out.Tags {
			tags[cfnComputeValue(v.Key)] = cfnComputeValue(v.Value)
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return tags, nil
		}
	}
}

// Identity Center instances and permission sets carry private incarnation
// claims; public tags are customer data and never establish ownership.
func cfnSSOUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, instance, arn string, current map[string]string) error {
	desired := cfnOrgIdentityTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if e := cfnComputeRun(ctx, c, "ssoadmin", "UntagResource", map[string]any{"InstanceArn": instance, "ResourceArn": arn, "TagKeys": removed}); e != nil {
			return e
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "ssoadmin", "TagResource", map[string]any{"InstanceArn": instance, "ResourceArn": arn, "Tags": cfnComputeTagList(desired)})
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sso-instance.html
type cfnSSOInstance struct{ commands StepFunctionsCommands }

func (h cfnSSOInstance) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "Name", "Tags"); e != nil {
		return e
	}
	if e := cfnComputeStrings(p, "Name"); e != nil {
		return e
	}
	_, e := cfnComputeTags(p)
	return e
}
func (h cfnSSOInstance) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}
func (h cfnSSOInstance) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	out, e := cfnOrgIdentityCall[api.CreateInstanceOutput](cfnOrgIdentityClaim(ctx, r), h.commands, "ssoadmin", "CreateInstance", map[string]any{"Name": cfnComputeDefault(r.Properties, "Name", ""), "ClientToken": r.Token, "Tags": cfnComputeTagList(cfnOrgIdentityTags(r))})
	if cfnMessagingMissing(e, "ConflictException") {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, e)
	}
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	r.PhysicalID = cfnComputeValue(out.InstanceArn)
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}

// RecoverCreation observes only the instance committed under this exact incarnation.
func (h cfnSSOInstance) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	out, e := cfnOrgIdentityCall[api.ListInstancesOutput](cfnOrgIdentityClaim(ctx, r), h.commands, "ssoadmin", "ListInstances", map[string]any{})
	if e != nil {
		return cloudformation.ResourceResult{}, cfnOrgIdentityUnobserved(e)
	}
	if len(out.Instances) == 0 {
		return cloudformation.ResourceResult{}, cfnOrgIdentityNotFound("Identity Center instance was not created by this incarnation")
	}
	r.PhysicalID = cfnComputeValue(out.Instances[0].InstanceArn)
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}
func (h cfnSSOInstance) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	owned := cfnOrgIdentityContext(ctx, r)
	if e := cfnComputeRun(owned, h.commands, "ssoadmin", "UpdateInstance", map[string]any{"InstanceArn": r.PhysicalID, "Name": cfnComputeDefault(r.Properties, "Name", "")}); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	tags, e := cfnSSOTags(owned, h.commands, r.PhysicalID, r.PhysicalID)
	if e == nil {
		e = cfnSSOUpdateTags(owned, h.commands, r, r.PhysicalID, r.PhysicalID, tags)
	}
	result, re := cfnOrgIdentityRefreshResult(ctx, h, r)
	if e != nil {
		return result, e
	}
	return result, re
}
func (h cfnSSOInstance) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	return cfnComputeAbsent(cfnComputeRun(cfnOrgIdentityContext(ctx, r), h.commands, "ssoadmin", "DeleteInstance", map[string]any{"InstanceArn": r.PhysicalID}))
}
func (h cfnSSOInstance) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, e := cfnOrgIdentityCall[api.DescribeInstanceOutput](ctx, h.commands, "ssoadmin", "DescribeInstance", map[string]any{"InstanceArn": r.PhysicalID})
	if e != nil {
		return nil, e
	}
	tags, e := cfnSSOTags(ctx, h.commands, r.PhysicalID, r.PhysicalID)
	if e != nil {
		return nil, e
	}
	return cloudformation.Properties{"InstanceArn": r.PhysicalID, "Name": cfnComputeValue(out.Name), "OwnerAccountId": cfnComputeValue(out.OwnerAccountId), "IdentityStoreId": cfnComputeValue(out.IdentityStoreId), "Status": cfnComputeValue(out.Status), "Tags": cfnResourcePublicTags(tags)}, nil
}
func (h cfnSSOInstance) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, e := h.Read(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnOrgIdentityResult(r.PhysicalID, p), nil
}
func (h cfnSSOInstance) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListInstancesOutput](ctx, h.commands, "ssoadmin", "ListInstances", map[string]any{"NextToken": next})
		if e != nil {
			return nil, e
		}
		for _, v := range out.Instances {
			r.PhysicalID = cfnComputeValue(v.InstanceArn)
			p, e := h.Read(ctx, r)
			if e != nil {
				return nil, e
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
	}
}
