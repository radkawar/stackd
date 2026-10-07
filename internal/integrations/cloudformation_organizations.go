package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/organizations"
	"stackd/internal/services/cloudformation"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-organizations-organization.html
type cfnOrganization struct{ commands StepFunctionsCommands }

func (h cfnOrganization) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "FeatureSet"); e != nil {
		return e
	}
	if e := cfnComputeStrings(p, "FeatureSet"); e != nil {
		return e
	}
	if v := cfnComputeString(p, "FeatureSet"); v != "" && v != "ALL" && v != "CONSOLIDATED_BILLING" {
		return fmt.Errorf("invalid FeatureSet")
	}
	return nil
}
func (h cfnOrganization) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}
func (h cfnOrganization) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	out, e := cfnOrgIdentityCall[api.CreateOrganizationOutput](cfnOrgIdentityContext(ctx, r), h.commands, "organizations", "CreateOrganization", cfnComputeCopy(r.Properties, "FeatureSet"))
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	r.PhysicalID = cfnComputeValue(out.Organization.Id)
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}
func (h cfnOrganization) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	out, e := cfnOrgIdentityCall[api.DescribeOrganizationOutput](cfnOrgIdentityContext(ctx, r), h.commands, "organizations", "DescribeOrganization", map[string]any{})
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	if cfnComputeValue(out.Organization.Id) != r.PhysicalID {
		return cloudformation.ResourceResult{}, fmt.Errorf("organization identity changed")
	}
	desired := cfnComputeDefault(r.Properties, "FeatureSet", "ALL")
	if desired != cfnComputeValue(out.Organization.FeatureSet) {
		if desired != "ALL" {
			return cloudformation.ResourceResult{}, fmt.Errorf("FeatureSet cannot be downgraded")
		}
		_, e = cfnOrgIdentityCall[api.EnableAllFeaturesOutput](ctx, h.commands, "organizations", "EnableAllFeatures", map[string]any{})
		if e != nil && !(cfnMessagingMissing(e, "HandshakeConstraintViolationException") && strings.Contains(e.Error(), "ORGANIZATION_IS_ALREADY_PENDING_ALL_FEATURES_MIGRATION")) {
			return cloudformation.ResourceResult{}, e
		}
	}
	result, e := cfnOrgIdentityRefreshResult(ctx, h, r)
	return result, e
}
func (h cfnOrganization) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	out, e := cfnOrgIdentityCall[api.DescribeOrganizationOutput](cfnOrgIdentityContext(ctx, r), h.commands, "organizations", "DescribeOrganization", map[string]any{})
	if cfnOrganizationsMissing(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if r.PhysicalID != "" && cfnComputeValue(out.Organization.Id) != r.PhysicalID {
		return fmt.Errorf("organization identity changed")
	}
	return cfnComputeRun(cfnOrgIdentityContext(ctx, r), h.commands, "organizations", "DeleteOrganization", map[string]any{})
}
func (h cfnOrganization) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, e := cfnOrgIdentityCall[api.DescribeOrganizationOutput](ctx, h.commands, "organizations", "DescribeOrganization", map[string]any{})
	if e != nil {
		return nil, e
	}
	o := out.Organization
	id := cfnComputeValue(o.Id)
	if r.PhysicalID != "" && id != r.PhysicalID {
		return nil, cfnOrgIdentityNotFound("organization not found")
	}
	root, e := cfnOrganizationsRoot(ctx, h.commands)
	if e != nil {
		return nil, e
	}
	return cloudformation.Properties{"Id": id, "Arn": cfnComputeValue(o.Arn), "FeatureSet": cfnComputeValue(o.FeatureSet), "ManagementAccountId": cfnComputeValue(o.MasterAccountId), "ManagementAccountArn": cfnComputeValue(o.MasterAccountArn), "ManagementAccountEmail": cfnComputeValue(o.MasterAccountEmail), "RootId": root}, nil
}
func (h cfnOrganization) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, e := h.Read(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnOrgIdentityResult(cfnComputeString(p, "Id"), p), nil
}
func (h cfnOrganization) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	r.PhysicalID = ""
	p, e := h.Read(ctx, r)
	if cfnOrganizationsMissing(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	return []cloudformation.ResourceDescription{{Identifier: cfnComputeString(p, "Id"), Properties: p}}, nil
}
func (h cfnOrganization) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	p, e := h.Read(ctx, r)
	if e != nil {
		return false, e
	}
	if p["FeatureSet"] == cfnComputeDefault(r.Properties, "FeatureSet", "ALL") {
		return true, nil
	}
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListHandshakesForOrganizationOutput](ctx, h.commands, "organizations", "ListHandshakesForOrganization", map[string]any{"Filter": map[string]any{"ActionType": "ENABLE_ALL_FEATURES"}, "NextToken": next})
		if e != nil {
			return false, e
		}
		for _, v := range out.Handshakes {
			if cfnComputeValue(v.Action) == "ENABLE_ALL_FEATURES" && cfnComputeValue(v.State) == "OPEN" {
				if e := cfnComputeRun(ctx, h.commands, "organizations", "AcceptHandshake", map[string]any{"HandshakeId": cfnComputeValue(v.Id)}); e != nil {
					return false, e
				}
				return false, nil
			}
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return false, nil
		}
	}
}
