package integrations

import (
	"context"
	"fmt"
	"reflect"

	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
)

type cfnIAMRole struct{ commands StepFunctionsCommands }

func (h cfnIAMRole) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "RoleName", "Path", "AssumeRolePolicyDocument", "Description", "MaxSessionDuration", "PermissionsBoundary", "ManagedPolicyArns", "Policies", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "AssumeRolePolicyDocument"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "RoleName", "Path", "Description", "PermissionsBoundary"); err != nil {
		return err
	}
	if _, err := cfnComputeDocument(p["AssumeRolePolicyDocument"]); err != nil {
		return err
	}
	if _, err := cfnComputeStringList(p, "ManagedPolicyArns"); err != nil {
		return err
	}
	if _, err := cfnIAMInlinePolicies(p); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func cfnIAMInlinePolicies(p map[string]any) (map[string]string, error) {
	out := map[string]string{}
	if p["Policies"] == nil {
		return out, nil
	}
	list, ok := p["Policies"].([]any)
	if !ok {
		return nil, fmt.Errorf("property Policies must be a list")
	}
	for _, item := range list {
		policy, ok := cfnComputeObject(item)
		if !ok {
			return nil, fmt.Errorf("property Policies entries must be objects")
		}
		if err := cfnComputeProperties(policy, "PolicyName", "PolicyDocument"); err != nil {
			return nil, err
		}
		name := cfnComputeString(policy, "PolicyName")
		if name == "" {
			return nil, fmt.Errorf("PolicyName is required")
		}
		if _, duplicate := out[name]; duplicate {
			return nil, fmt.Errorf("duplicate PolicyName %s", name)
		}
		document, err := cfnComputeDocument(policy["PolicyDocument"])
		if err != nil {
			return nil, err
		}
		out[name] = document
	}
	return out, nil
}
func (h cfnIAMRole) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "RoleName") || !reflect.DeepEqual(cfnComputeDefault(a, "Path", "/"), cfnComputeDefault(b, "Path", "/")), nil
}
func (h cfnIAMRole) owned(ctx context.Context, r cloudformation.ResourceRequest, name string) (*api.Role, error) {
	ctx = cfnIAMContext(ctx, r)
	out, err := cfnComputeCall[api.GetRoleOutput](ctx, h.commands, "iam", "GetRole", map[string]any{"RoleName": name})
	if err != nil {
		return nil, err
	}
	if out.Role == nil {
		return nil, fmt.Errorf("IAM returned no role")
	}
	return out.Role, nil
}
func cfnIAMRoleResult(role *api.Role) cloudformation.ResourceResult {
	name := cfnComputeValue(role.RoleName)
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": cfnComputeValue(role.Arn), "RoleId": cfnComputeValue(role.RoleId)}}
}
func (h cfnIAMRole) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "RoleName", 64)
	role, err := h.owned(ctx, r, name)
	if err != nil && !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if cfnComputeMissing(err) {
		input := cfnComputeCopy(r.Properties, "Path", "Description", "MaxSessionDuration", "PermissionsBoundary")
		input["RoleName"] = name
		input["Tags"] = cfnComputeTagList(cfnIAMCustomerTags(r))
		input["AssumeRolePolicyDocument"], _ = cfnComputeDocument(r.Properties["AssumeRolePolicyDocument"])
		out, err := cfnComputeCall[api.CreateRoleOutput](ctx, h.commands, "iam", "CreateRole", input)
		if err != nil {
			return cfnIAMCreationFailure(ctx, r, h, err)
		}
		role = out.Role
	}
	result := cfnIAMRoleResult(role)
	return result, h.policies(ctx, r, name)
}
func (h cfnIAMRole) policies(ctx context.Context, r cloudformation.ResourceRequest, name string) error {
	return cfnIAMReconcilePolicies(ctx, h.commands, r, "Role", name)
}
func (h cfnIAMRole) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	role, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnIAMRoleResult(role)
	document, _ := cfnComputeDocument(r.Properties["AssumeRolePolicyDocument"])
	if err := cfnComputeRun(ctx, h.commands, "iam", "UpdateAssumeRolePolicy", map[string]any{"RoleName": r.PhysicalID, "PolicyDocument": document}); err != nil {
		return result, err
	}
	if err := cfnComputeRun(ctx, h.commands, "iam", "UpdateRole", map[string]any{"RoleName": r.PhysicalID, "Description": cfnComputeDefault(r.Properties, "Description", ""), "MaxSessionDuration": cfnComputeDefault(r.Properties, "MaxSessionDuration", 3600)}); err != nil {
		return result, err
	}
	boundary := cfnComputeString(r.Properties, "PermissionsBoundary")
	if boundary != "" {
		err = cfnComputeRun(ctx, h.commands, "iam", "PutRolePermissionsBoundary", map[string]any{"RoleName": r.PhysicalID, "PermissionsBoundary": boundary})
	} else if role.PermissionsBoundary != nil {
		err = cfnComputeRun(ctx, h.commands, "iam", "DeleteRolePermissionsBoundary", map[string]any{"RoleName": r.PhysicalID})
	}
	if err != nil {
		return result, err
	}
	if err := h.policies(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	return result, cfnIAMUpdateTags(ctx, h.commands, r, "Role", "RoleName", r.PhysicalID, cfnIAMTags(role.Tags))
}
func (h cfnIAMRole) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnIAMContext(ctx, r)
	name := cfnComputeName(r, "RoleName", 64)
	if _, err := h.owned(ctx, r, name); err != nil {
		return cfnComputeAbsent(err)
	}
	r.Previous = r.Properties
	r.Properties = cloudformation.Properties{}
	if err := h.policies(ctx, r, name); err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "iam", "DeleteRole", map[string]any{"RoleName": name}))
}
