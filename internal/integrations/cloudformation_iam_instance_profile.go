package integrations

import (
	"context"
	"reflect"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-instanceprofile.html
// Profile membership remains IAM's immutable RoleId association, not CFN state.
type cfnIAMInstanceProfile struct{ commands StepFunctionsCommands }

func (h cfnIAMInstanceProfile) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "InstanceProfileName", "Path", "Roles"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "InstanceProfileName", "Path"); err != nil {
		return err
	}
	return cfnIAMRequireList(p, "Roles", 1)
}
func (h cfnIAMInstanceProfile) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "InstanceProfileName") || !reflect.DeepEqual(cfnComputeDefault(a, "Path", "/"), cfnComputeDefault(b, "Path", "/")), nil
}
func (h cfnIAMInstanceProfile) owned(ctx context.Context, r cloudformation.ResourceRequest, name string) (*api.InstanceProfile, error) {
	ctx = cfnIAMContext(ctx, r)
	out, err := cfnComputeCall[api.GetInstanceProfileOutput](ctx, h.commands, "iam", "GetInstanceProfile", map[string]any{"InstanceProfileName": name})
	if err != nil {
		return nil, err
	}
	if out.InstanceProfile == nil {
		return nil, cfnIAMNotFound()
	}
	return out.InstanceProfile, nil
}
func (h cfnIAMInstanceProfile) roles(ctx context.Context, r cloudformation.ResourceRequest, p *api.InstanceProfile) error {
	desired, _ := cfnComputeStringList(r.Properties, "Roles")
	name := cfnComputeValue(p.InstanceProfileName)
	for _, role := range p.Roles {
		existing := cfnComputeValue(role.RoleName)
		if len(desired) == 1 && desired[0] == existing {
			return nil
		}
		if err := cfnComputeRun(ctx, h.commands, "iam", "RemoveRoleFromInstanceProfile", map[string]any{"InstanceProfileName": name, "RoleName": existing}); err != nil {
			return err
		}
	}
	if len(desired) == 1 {
		return cfnComputeRun(ctx, h.commands, "iam", "AddRoleToInstanceProfile", map[string]any{"InstanceProfileName": name, "RoleName": desired[0]})
	}
	return nil
}
func (h cfnIAMInstanceProfile) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "InstanceProfileName", 128)
	p, err := h.owned(ctx, r, name)
	if err != nil && !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if cfnComputeMissing(err) {
		out, e := cfnComputeCall[api.CreateInstanceProfileOutput](ctx, h.commands, "iam", "CreateInstanceProfile", map[string]any{"InstanceProfileName": name, "Path": cfnComputeDefault(r.Properties, "Path", "/"), "Tags": cfnComputeTagList(cfnIAMCustomerTags(r))})
		if e != nil {
			return cfnIAMCreationFailure(ctx, r, h, e)
		}
		p = out.InstanceProfile
	}
	result := cfnIAMNamedResult(name, cfnComputeValue(p.Arn))
	return result, h.roles(ctx, r, p)
}
func (h cfnIAMInstanceProfile) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	p, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnIAMNamedResult(r.PhysicalID, cfnComputeValue(p.Arn)), h.roles(ctx, r, p)
}
func (h cfnIAMInstanceProfile) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnIAMContext(ctx, r)
	p, err := h.owned(ctx, r, cfnComputeName(r, "InstanceProfileName", 128))
	if err != nil {
		return cfnComputeAbsent(err)
	}
	r.Properties = cloudformation.Properties{"Roles": []any{}}
	if err := h.roles(ctx, r, p); err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "iam", "DeleteInstanceProfile", map[string]any{"InstanceProfileName": cfnComputeValue(p.InstanceProfileName)}))
}
func (h cfnIAMInstanceProfile) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	p, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	roles := []string{}
	for _, role := range p.Roles {
		roles = append(roles, cfnComputeValue(role.RoleName))
	}
	return cloudformation.Properties{"InstanceProfileName": cfnComputeValue(p.InstanceProfileName), "Path": cfnComputeValue(p.Path), "Roles": roles, "Arn": cfnComputeValue(p.Arn)}, nil
}
func (h cfnIAMInstanceProfile) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListInstanceProfilesOutput](ctx, h.commands, "iam", "ListInstanceProfiles", in)
		if err != nil {
			return nil, err
		}
		for _, p := range out.InstanceProfiles {
			rr := r
			rr.PhysicalID = cfnComputeValue(p.InstanceProfileName)
			model, e := h.Read(ctx, rr)
			if e != nil {
				return nil, e
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: model})
		}
		marker := cfnComputeValue(out.Marker)
		if marker == "" {
			return result, nil
		}
		in["Marker"] = marker
	}
}
