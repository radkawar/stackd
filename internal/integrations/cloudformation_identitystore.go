package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/identitystore"
	sso "stackd/internal/awsapi/ssoadmin"
	"stackd/internal/services/cloudformation"
)

// Native directory APIs preserve directory admission and scoped IAM authorization.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-identitystore-group.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-identitystore-groupmembership.html
type cfnIdentityGroup struct{ commands StepFunctionsCommands }

func (h cfnIdentityGroup) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "IdentityStoreId", "DisplayName", "Description"); e != nil {
		return e
	}
	if e := cfnComputeRequired(p, "IdentityStoreId", "DisplayName"); e != nil {
		return e
	}
	return cfnComputeStrings(p, "IdentityStoreId", "DisplayName", "Description")
}
func (h cfnIdentityGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "IdentityStoreId"), h.Validate(b)
}
func (h cfnIdentityGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	out, e := cfnOrgIdentityCall[api.CreateGroupOutput](cfnOrgIdentityContext(ctx, r), h.commands, "identitystore", "CreateGroup", cfnComputeCopy(r.Properties, "IdentityStoreId", "DisplayName", "Description"))
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	id := cfnOrgIdentityID(cfnComputeValue(out.GroupId), cfnComputeValue(out.IdentityStoreId))
	return cfnOrgIdentityResult(id, cloudformation.Properties{"GroupId": cfnComputeValue(out.GroupId), "IdentityStoreId": cfnComputeValue(out.IdentityStoreId)}), nil
}
func (h cfnIdentityGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	ops := []map[string]any{{"AttributePath": "displayName", "AttributeValue": r.Properties["DisplayName"]}, {"AttributePath": "description", "AttributeValue": r.Properties["Description"]}}
	e = cfnComputeRun(cfnOrgIdentityContext(ctx, r), h.commands, "identitystore", "UpdateGroup", map[string]any{"IdentityStoreId": parts[1], "GroupId": parts[0], "Operations": ops})
	return cfnOrgIdentityResult(r.PhysicalID, cloudformation.Properties{"GroupId": parts[0], "IdentityStoreId": parts[1]}), e
}
func (h cfnIdentityGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return e
	}
	return cfnComputeAbsent(cfnComputeRun(cfnOrgIdentityContext(ctx, r), h.commands, "identitystore", "DeleteGroup", map[string]any{"IdentityStoreId": parts[1], "GroupId": parts[0]}))
}
func (h cfnIdentityGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return nil, e
	}
	out, e := cfnOrgIdentityCall[api.DescribeGroupOutput](ctx, h.commands, "identitystore", "DescribeGroup", map[string]any{"IdentityStoreId": parts[1], "GroupId": parts[0]})
	if e != nil {
		return nil, e
	}
	return cloudformation.Properties{"GroupId": parts[0], "IdentityStoreId": parts[1], "DisplayName": cfnComputeValue(out.DisplayName), "Description": cfnComputeValue(out.Description)}, nil
}
func (h cfnIdentityGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	stores, e := cfnIdentityStoreIDs(ctx, h.commands, cfnComputeString(r.Properties, "IdentityStoreId"))
	if e != nil {
		return nil, e
	}
	var rows []cloudformation.ResourceDescription
	for _, store := range stores {
		next := ""
		for {
			out, e := cfnOrgIdentityCall[api.ListGroupsOutput](ctx, h.commands, "identitystore", "ListGroups", map[string]any{"IdentityStoreId": store, "NextToken": next})
			if e != nil {
				return nil, e
			}
			for _, g := range out.Groups {
				id := cfnOrgIdentityID(cfnComputeValue(g.GroupId), store)
				p := cloudformation.Properties{"GroupId": cfnComputeValue(g.GroupId), "IdentityStoreId": store, "DisplayName": cfnComputeValue(g.DisplayName), "Description": cfnComputeValue(g.Description)}
				rows = append(rows, cloudformation.ResourceDescription{Identifier: id, Properties: p})
			}
			next = cfnComputeValue(out.NextToken)
			if next == "" {
				break
			}
		}
	}
	return rows, nil
}

type cfnIdentityMembership struct{ commands StepFunctionsCommands }

func (h cfnIdentityMembership) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "IdentityStoreId", "GroupId", "MemberId"); e != nil {
		return e
	}
	if e := cfnComputeRequired(p, "IdentityStoreId", "GroupId", "MemberId"); e != nil {
		return e
	}
	if e := cfnComputeStrings(p, "IdentityStoreId", "GroupId"); e != nil {
		return e
	}
	m, ok := cfnComputeObject(p["MemberId"])
	if !ok {
		return fmt.Errorf("MemberId must be an object")
	}
	if e := cfnComputeProperties(m, "UserId"); e != nil {
		return e
	}
	if e := cfnComputeRequired(m, "UserId"); e != nil {
		return e
	}
	return cfnComputeStrings(m, "UserId")
}
func (h cfnIdentityMembership) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "IdentityStoreId", "GroupId", "MemberId"), h.Validate(b)
}
func (h cfnIdentityMembership) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	out, e := cfnOrgIdentityCall[api.CreateGroupMembershipOutput](cfnOrgIdentityContext(ctx, r), h.commands, "identitystore", "CreateGroupMembership", cfnComputeCopy(r.Properties, "IdentityStoreId", "GroupId", "MemberId"))
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	id := cfnOrgIdentityID(cfnComputeValue(out.MembershipId), cfnComputeValue(out.IdentityStoreId))
	return cfnOrgIdentityResult(id, cloudformation.Properties{"MembershipId": cfnComputeValue(out.MembershipId), "IdentityStoreId": cfnComputeValue(out.IdentityStoreId)}), nil
}
func (h cfnIdentityMembership) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, e := h.Read(cfnOrgIdentityContext(ctx, r), r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnOrgIdentityResult(r.PhysicalID, p), nil
}
func (h cfnIdentityMembership) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return e
	}
	return cfnComputeAbsent(cfnComputeRun(cfnOrgIdentityContext(ctx, r), h.commands, "identitystore", "DeleteGroupMembership", map[string]any{"IdentityStoreId": parts[1], "MembershipId": parts[0]}))
}
func (h cfnIdentityMembership) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return nil, e
	}
	out, e := cfnOrgIdentityCall[api.DescribeGroupMembershipOutput](ctx, h.commands, "identitystore", "DescribeGroupMembership", map[string]any{"IdentityStoreId": parts[1], "MembershipId": parts[0]})
	if e != nil {
		return nil, e
	}
	return cloudformation.Properties{"IdentityStoreId": parts[1], "MembershipId": parts[0], "GroupId": cfnComputeValue(out.GroupId), "MemberId": map[string]any{"UserId": cfnComputeValue(out.MemberId.UserId)}}, nil
}
func (h cfnIdentityMembership) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	stores, e := cfnIdentityStoreIDs(ctx, h.commands, cfnComputeString(r.Properties, "IdentityStoreId"))
	if e != nil {
		return nil, e
	}
	var rows []cloudformation.ResourceDescription
	for _, store := range stores {
		group := cfnComputeString(r.Properties, "GroupId")
		groups := []string{group}
		if group == "" {
			query := r
			query.Properties = cloudformation.Properties{"IdentityStoreId": store}
			gs, e := (cfnIdentityGroup(h)).List(ctx, query)
			if e != nil {
				return nil, e
			}
			groups = nil
			for _, g := range gs {
				groups = append(groups, cfnComputeString(g.Properties, "GroupId"))
			}
		}
		for _, g := range groups {
			next := ""
			for {
				out, e := cfnOrgIdentityCall[api.ListGroupMembershipsOutput](ctx, h.commands, "identitystore", "ListGroupMemberships", map[string]any{"IdentityStoreId": store, "GroupId": g, "NextToken": next})
				if e != nil {
					return nil, e
				}
				for _, m := range out.GroupMemberships {
					id := cfnOrgIdentityID(cfnComputeValue(m.MembershipId), store)
					rows = append(rows, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"IdentityStoreId": store, "MembershipId": cfnComputeValue(m.MembershipId), "GroupId": g, "MemberId": map[string]any{"UserId": cfnComputeValue(m.MemberId.UserId)}}})
				}
				next = cfnComputeValue(out.NextToken)
				if next == "" {
					break
				}
			}
		}
	}
	return rows, nil
}

func cfnIdentityStoreIDs(ctx context.Context, c StepFunctionsCommands, selected string) ([]string, error) {
	if selected != "" {
		return []string{selected}, nil
	}
	var stores []string
	next := ""
	for {
		out, e := cfnOrgIdentityCall[sso.ListInstancesOutput](ctx, c, "ssoadmin", "ListInstances", map[string]any{"NextToken": next})
		if e != nil {
			return nil, e
		}
		for _, v := range out.Instances {
			stores = append(stores, cfnComputeValue(v.IdentityStoreId))
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return stores, nil
		}
	}
}
