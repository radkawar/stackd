package integrations

import (
	"context"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-role.html
func (h cfnIAMRole) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	role, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnIAMIdentityPolicies(ctx, h.commands, "Role", r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p["RoleName"] = cfnComputeValue(role.RoleName)
	p["Path"] = cfnComputeValue(role.Path)
	p["Arn"] = cfnComputeValue(role.Arn)
	p["RoleId"] = cfnComputeValue(role.RoleId)
	p["AssumeRolePolicyDocument"] = cfnIAMDocument(cfnComputeValue(role.AssumeRolePolicyDocument))
	p["Description"] = cfnComputeValue(role.Description)
	if role.MaxSessionDuration != nil {
		p["MaxSessionDuration"] = int64(*role.MaxSessionDuration)
	}
	if role.PermissionsBoundary != nil {
		p["PermissionsBoundary"] = cfnComputeValue(role.PermissionsBoundary.PermissionsBoundaryArn)
	}
	p["Tags"] = cfnIAMUserTags(role.Tags)
	return p, nil
}
func (h cfnIAMRole) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListRolesOutput](ctx, h.commands, "iam", "ListRoles", in)
		if err != nil {
			return nil, err
		}
		for _, role := range out.Roles {
			rr := r
			rr.PhysicalID = cfnComputeValue(role.RoleName)
			p, e := h.Read(ctx, rr)
			if e != nil {
				if !r.CloudControl {
					continue
				}
				return nil, e
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
		}
		marker := cfnComputeValue(out.Marker)
		if marker == "" {
			return result, nil
		}
		in["Marker"] = marker
	}
}
func (h cfnIAMRole) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	role, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnIAMRoleResult(role), nil
}
