package integrations

import (
	"context"
	api "stackd/internal/awsapi/organizations"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-organizations-organizationalunit.html
type cfnOrganizationUnit struct{ commands StepFunctionsCommands }

func (h cfnOrganizationUnit) Validate(p cloudformation.Properties) error {
	if e := cfnOrganizationsValidate(p, []string{"Name", "ParentId"}, "Name", "ParentId", "Tags"); e != nil {
		return e
	}
	return cfnComputeStrings(p, "Name", "ParentId")
}
func (h cfnOrganizationUnit) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ParentId"), h.Validate(b)
}

// Units carry a private incarnation claim. Native same-name siblings and public
// tags are never adopted; Cloud Control direct mutations remain IAM-only.
func (h cfnOrganizationUnit) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	input := cfnComputeCopy(r.Properties, "Name", "ParentId")
	input["Tags"] = cfnComputeTagList(cfnOrgIdentityTags(r))
	out, e := cfnOrgIdentityCall[api.CreateOrganizationalUnitOutput](cfnOrgIdentityClaim(ctx, r), h.commands, "organizations", "CreateOrganizationalUnit", input)
	if cfnMessagingMissing(e, "DuplicateOrganizationalUnitException") {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, e)
	}
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	r.PhysicalID = cfnComputeValue(out.OrganizationalUnit.Id)
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}

// RecoverCreation observes only the unit committed under this exact incarnation.
func (h cfnOrganizationUnit) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	rows, e := h.children(cfnOrgIdentityClaim(ctx, r), cfnComputeString(r.Properties, "ParentId"))
	if e != nil {
		return cloudformation.ResourceResult{}, cfnOrgIdentityUnobserved(e)
	}
	if len(rows) == 0 {
		return cloudformation.ResourceResult{}, cfnOrgIdentityNotFound("organizational unit was not created by this incarnation")
	}
	r.PhysicalID = cfnComputeValue(rows[0].Id)
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}
func (h cfnOrganizationUnit) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	owned := cfnOrgIdentityContext(ctx, r)
	if e := cfnComputeRun(owned, h.commands, "organizations", "UpdateOrganizationalUnit", map[string]any{"OrganizationalUnitId": r.PhysicalID, "Name": r.Properties["Name"]}); e != nil {
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
func (h cfnOrganizationUnit) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	e := cfnComputeRun(cfnOrgIdentityContext(ctx, r), h.commands, "organizations", "DeleteOrganizationalUnit", map[string]any{"OrganizationalUnitId": r.PhysicalID})
	if cfnOrganizationsMissing(e) {
		return nil
	}
	return e
}
func (h cfnOrganizationUnit) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, e := cfnOrgIdentityCall[api.DescribeOrganizationalUnitOutput](ctx, h.commands, "organizations", "DescribeOrganizationalUnit", map[string]any{"OrganizationalUnitId": r.PhysicalID})
	if e != nil {
		return nil, e
	}
	tags, e := cfnOrganizationsTags(ctx, h.commands, r.PhysicalID)
	if e != nil {
		return nil, e
	}
	parent, e := cfnOrganizationsParent(ctx, h.commands, r.PhysicalID)
	if e != nil {
		return nil, e
	}
	path, e := cfnOrganizationsPath(ctx, h.commands, r.PhysicalID)
	if e != nil {
		return nil, e
	}
	u := out.OrganizationalUnit
	return cloudformation.Properties{"Id": r.PhysicalID, "Arn": cfnComputeValue(u.Arn), "Name": cfnComputeValue(u.Name), "ParentId": parent, "Path": path, "Tags": cfnResourcePublicTags(tags)}, nil
}
func (h cfnOrganizationUnit) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, e := h.Read(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnOrgIdentityResult(r.PhysicalID, p), nil
}
func (h cfnOrganizationUnit) children(ctx context.Context, parent string) ([]api.OrganizationalUnit, error) {
	var rows []api.OrganizationalUnit
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListOrganizationalUnitsForParentOutput](ctx, h.commands, "organizations", "ListOrganizationalUnitsForParent", map[string]any{"ParentId": parent, "NextToken": next})
		if e != nil {
			return nil, e
		}
		rows = append(rows, out.OrganizationalUnits...)
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
	}
}
func (h cfnOrganizationUnit) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	root, e := cfnOrganizationsRoot(ctx, h.commands)
	if e != nil {
		return nil, e
	}
	parents := []string{root}
	var rows []cloudformation.ResourceDescription
	for len(parents) > 0 {
		parent := parents[0]
		parents = parents[1:]
		children, e := h.children(ctx, parent)
		if e != nil {
			return nil, e
		}
		for _, u := range children {
			r.PhysicalID = cfnComputeValue(u.Id)
			p, e := h.Read(ctx, r)
			if e != nil {
				return nil, e
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
			parents = append(parents, r.PhysicalID)
		}
	}
	return rows, nil
}
