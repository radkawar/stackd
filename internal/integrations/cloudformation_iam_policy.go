package integrations

import (
	"context"
	"fmt"
	"slices"

	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
)

// IAM inline policies have no tag API. The containing stack-owned role holds a
// per-policy ownership tag, written before PutRolePolicy so recovery can finish
// a partially applied multi-role policy without adopting a pre-existing policy.
// User/group policies remain unsupported because their ownership is not managed.
type cfnIAMPolicy struct{ commands StepFunctionsCommands }

func (h cfnIAMPolicy) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "PolicyName", "PolicyDocument", "Roles"); err != nil {
		return err
	}
	if name := cfnComputeString(p, "PolicyName"); name == "" {
		return fmt.Errorf("PolicyName is required")
	}
	if _, err := cfnComputeDocument(p["PolicyDocument"]); err != nil {
		return err
	}
	roles, err := cfnComputeStringList(p, "Roles")
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		return fmt.Errorf("inline Policy requires at least one stack-owned Role")
	}
	return nil
}
func (h cfnIAMPolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return false, nil
}
func cfnIAMPolicyMarker(name string) string {
	return cfnComputeTagPrefix + "policy-" + cfnComputeHash(name)
}
func cfnIAMPolicyOwner(r cloudformation.ResourceRequest) string {
	return cfnComputeHash(r.StackID + "/" + r.LogicalID + "/" + r.Token)
}
func (h cfnIAMPolicy) role(ctx context.Context, r cloudformation.ResourceRequest, name string) (*api.Role, error) {
	out, err := cfnComputeCall[api.GetRoleOutput](ctx, h.commands, "iam", "GetRole", map[string]any{"RoleName": name})
	if err != nil {
		return nil, err
	}
	if out.Role == nil {
		return nil, fmt.Errorf("IAM returned no role")
	}
	for _, tag := range out.Role.Tags {
		if cfnComputeValue(tag.Key) == cfnComputeTagPrefix+"stack-id" && cfnComputeValue(tag.Value) == r.StackID {
			return out.Role, nil
		}
	}
	return nil, fmt.Errorf("inline IAM policies support only roles owned by this stack")
}
func cfnIAMPolicyClaim(role *api.Role, name string) string {
	for _, tag := range role.Tags {
		if cfnComputeValue(tag.Key) == cfnIAMPolicyMarker(name) {
			return cfnComputeValue(tag.Value)
		}
	}
	return ""
}
func (h cfnIAMPolicy) put(ctx context.Context, r cloudformation.ResourceRequest, roleName, name, document string) (bool, error) {
	role, err := h.role(ctx, r, roleName)
	if err != nil {
		return false, err
	}
	claim := cfnIAMPolicyClaim(role, name)
	owner := cfnIAMPolicyOwner(r)
	if claim != "" && claim != owner {
		return false, fmt.Errorf("inline policy %s on %s is owned by another resource", name, roleName)
	}
	if claim == "" {
		_, err := cfnComputeCall[api.GetRolePolicyOutput](ctx, h.commands, "iam", "GetRolePolicy", map[string]any{"RoleName": roleName, "PolicyName": name})
		if err == nil {
			return false, fmt.Errorf("inline policy %s on %s already exists and is not owned", name, roleName)
		}
		if !cfnComputeMissing(err) {
			return false, err
		}
		if err := cfnComputeRun(ctx, h.commands, "iam", "TagRole", map[string]any{"RoleName": roleName, "Tags": []map[string]string{{"Key": cfnIAMPolicyMarker(name), "Value": owner}}}); err != nil {
			return false, err
		}
	}
	return true, cfnComputeRun(ctx, h.commands, "iam", "PutRolePolicy", map[string]any{"RoleName": roleName, "PolicyName": name, "PolicyDocument": document})
}
func (h cfnIAMPolicy) remove(ctx context.Context, r cloudformation.ResourceRequest, roleName, name string) error {
	out, err := cfnComputeCall[api.GetRoleOutput](ctx, h.commands, "iam", "GetRole", map[string]any{"RoleName": roleName})
	if err != nil {
		return cfnComputeAbsent(err)
	}
	if out.Role == nil {
		return fmt.Errorf("IAM returned no role")
	}
	claim := cfnIAMPolicyClaim(out.Role, name)
	if claim == "" {
		return nil
	}
	if claim != cfnIAMPolicyOwner(r) {
		return fmt.Errorf("inline policy %s on %s is not owned by this resource", name, roleName)
	}
	if err := cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "iam", "DeleteRolePolicy", map[string]any{"RoleName": roleName, "PolicyName": name})); err != nil {
		return err
	}
	return cfnComputeRun(ctx, h.commands, "iam", "UntagRole", map[string]any{"RoleName": roleName, "TagKeys": []string{cfnIAMPolicyMarker(name)}})
}
func (h cfnIAMPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeString(r.Properties, "PolicyName")
	document, _ := cfnComputeDocument(r.Properties["PolicyDocument"])
	roles, _ := cfnComputeStringList(r.Properties, "Roles")
	result := cloudformation.ResourceResult{}
	for _, role := range roles {
		owned, err := h.put(ctx, r, role, name, document)
		if owned {
			result = cloudformation.ResourceResult{PhysicalID: name, Ref: name}
		}
		if err != nil {
			return result, err
		}
	}
	return result, nil
}
func (h cfnIAMPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result, err := h.Create(ctx, r)
	if err != nil {
		return result, err
	}
	name := cfnComputeString(r.Properties, "PolicyName")
	previous := cfnComputeString(r.Previous, "PolicyName")
	desired, _ := cfnComputeStringList(r.Properties, "Roles")
	old, _ := cfnComputeStringList(r.Previous, "Roles")
	for _, role := range old {
		if name != previous || !slices.Contains(desired, role) {
			if err := h.remove(ctx, r, role, previous); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}
func (h cfnIAMPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeString(r.Properties, "PolicyName")
	roles, _ := cfnComputeStringList(r.Properties, "Roles")
	for _, role := range roles {
		if err := h.remove(ctx, r, role, name); err != nil {
			return err
		}
	}
	return nil
}
