package integrations

import (
	"context"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-group.html
type cfnIAMGroup struct{ commands StepFunctionsCommands }

func (h cfnIAMGroup) Validate(p cloudformation.Properties) error {
	if err := cfnIAMValidateIdentity(p, "GroupName", "Path", "Policies", "ManagedPolicyArns"); err != nil {
		return err
	}
	return cfnComputeStrings(p, "GroupName")
}
func (h cfnIAMGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "GroupName"), h.Validate(b)
}
func (h cfnIAMGroup) owned(ctx context.Context, r cloudformation.ResourceRequest, name string) (*api.Group, error) {
	out, err := cfnComputeCall[api.GetGroupOutput](cfnIAMContext(ctx, r), h.commands, "iam", "GetGroup", map[string]any{"GroupName": name})
	if err != nil {
		return nil, err
	}
	if out.Group == nil {
		return nil, cfnIAMNotFound()
	}
	return out.Group, nil
}
func (h cfnIAMGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "GroupName", 128)
	out, err := cfnComputeCall[api.CreateGroupOutput](cfnIAMContext(ctx, r), h.commands, "iam", "CreateGroup", map[string]any{"GroupName": name, "Path": cfnComputeDefault(r.Properties, "Path", "/")})
	if err != nil {
		return cfnIAMCreationFailure(ctx, r, h, err)
	}
	result := cfnIAMNamedResult(name, cfnComputeValue(out.Group.Arn))
	return result, cfnIAMReconcilePolicies(ctx, h.commands, r, "Group", name)
}
func (h cfnIAMGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	g, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnIAMNamedResult(r.PhysicalID, cfnComputeValue(g.Arn))
	if err := cfnComputeRun(cfnIAMContext(ctx, r), h.commands, "iam", "UpdateGroup", map[string]any{"GroupName": r.PhysicalID, "NewPath": cfnComputeDefault(r.Properties, "Path", "/")}); err != nil {
		return result, err
	}
	if err := cfnIAMReconcilePolicies(ctx, h.commands, r, "Group", r.PhysicalID); err != nil {
		return result, err
	}
	g, err = h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return result, err
	}
	return cfnIAMNamedResult(r.PhysicalID, cfnComputeValue(g.Arn)), nil
}
func (h cfnIAMGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeName(r, "GroupName", 128)
	if _, err := h.owned(ctx, r, name); err != nil {
		return cfnComputeAbsent(err)
	}
	r.Previous = r.Properties
	r.Properties = cloudformation.Properties{}
	if err := cfnIAMReconcilePolicies(ctx, h.commands, r, "Group", name); err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(cfnIAMContext(ctx, r), h.commands, "iam", "DeleteGroup", map[string]any{"GroupName": name}))
}
func (h cfnIAMGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	g, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnIAMIdentityPolicies(ctx, h.commands, "Group", r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p["GroupName"] = cfnComputeValue(g.GroupName)
	p["Path"] = cfnComputeValue(g.Path)
	p["Arn"] = cfnComputeValue(g.Arn)
	return p, nil
}
func (h cfnIAMGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListGroupsOutput](ctx, h.commands, "iam", "ListGroups", in)
		if err != nil {
			return nil, err
		}
		for _, g := range out.Groups {
			rr := r
			rr.PhysicalID = cfnComputeValue(g.GroupName)
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
