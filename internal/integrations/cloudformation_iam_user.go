package integrations

import (
	"context"
	"fmt"
	"slices"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-user.html
// Passwords are write-only: reads and resource attributes never return them.
type cfnIAMUser struct{ commands StepFunctionsCommands }

func (h cfnIAMUser) Validate(p cloudformation.Properties) error {
	if err := cfnIAMValidateIdentity(p, "UserName", "Path", "PermissionsBoundary", "ManagedPolicyArns", "Policies", "Groups", "LoginProfile", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "UserName", "PermissionsBoundary"); err != nil {
		return err
	}
	if _, err := cfnComputeStringList(p, "Groups"); err != nil {
		return err
	}
	if p["LoginProfile"] != nil {
		profile, ok := cfnComputeObject(p["LoginProfile"])
		if !ok {
			return fmt.Errorf("LoginProfile must be an object")
		}
		if err := cfnComputeProperties(profile, "Password", "PasswordResetRequired"); err != nil {
			return err
		}
		if err := cfnComputeRequired(profile, "Password"); err != nil {
			return err
		}
		if err := cfnComputeStrings(profile, "Password"); err != nil {
			return err
		}
		if v, ok := profile["PasswordResetRequired"]; ok {
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("PasswordResetRequired must be boolean")
			}
		}
	}
	return nil
}
func (h cfnIAMUser) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "UserName"), h.Validate(b)
}
func (h cfnIAMUser) owned(ctx context.Context, r cloudformation.ResourceRequest, name string) (*api.User, error) {
	ctx = cfnIAMContext(ctx, r)
	out, err := cfnComputeCall[api.GetUserOutput](ctx, h.commands, "iam", "GetUser", map[string]any{"UserName": name})
	if err != nil {
		return nil, err
	}
	if out.User == nil {
		return nil, cfnIAMNotFound()
	}
	return out.User, nil
}
func (h cfnIAMUser) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "UserName", 64)
	u, err := h.owned(ctx, r, name)
	if err != nil && !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if cfnComputeMissing(err) {
		in := cfnComputeCopy(r.Properties, "Path", "PermissionsBoundary")
		in["UserName"] = name
		in["Tags"] = cfnComputeTagList(cfnIAMCustomerTags(r))
		out, e := cfnComputeCall[api.CreateUserOutput](ctx, h.commands, "iam", "CreateUser", in)
		if e != nil {
			return cfnIAMCreationFailure(ctx, r, h, e)
		}
		u = out.User
	}
	result := cfnIAMNamedResult(name, cfnComputeValue(u.Arn))
	return result, h.configure(ctx, r, u)
}
func (h cfnIAMUser) configure(ctx context.Context, r cloudformation.ResourceRequest, u *api.User) error {
	name := cfnComputeValue(u.UserName)
	if err := cfnIAMReconcilePolicies(ctx, h.commands, r, "User", name); err != nil {
		return err
	}
	groups, _ := cfnComputeStringList(r.Properties, "Groups")
	old, _ := cfnComputeStringList(r.Previous, "Groups")
	for _, group := range groups {
		if err := cfnComputeRun(cfnIAMContext(ctx, r), h.commands, "iam", "AddUserToGroup", map[string]any{"UserName": name, "GroupName": group}); err != nil {
			return err
		}
	}
	for _, group := range old {
		if !slices.Contains(groups, group) {
			if err := cfnComputeAbsent(cfnComputeRun(cfnIAMContext(ctx, r), h.commands, "iam", "RemoveUserFromGroup", map[string]any{"UserName": name, "GroupName": group})); err != nil {
				return err
			}
		}
	}
	profile, desired := cfnComputeObject(r.Properties["LoginProfile"])
	_, err := cfnComputeCall[api.GetLoginProfileOutput](ctx, h.commands, "iam", "GetLoginProfile", map[string]any{"UserName": name})
	if err != nil && !cfnComputeMissing(err) {
		return err
	}
	if desired {
		in := cfnComputeCopy(profile, "Password", "PasswordResetRequired")
		in["UserName"] = name
		op := "UpdateLoginProfile"
		if cfnComputeMissing(err) {
			op = "CreateLoginProfile"
		}
		if err := cfnComputeRun(ctx, h.commands, "iam", op, in); err != nil {
			return err
		}
	} else if r.Previous["LoginProfile"] != nil && err == nil {
		if err := cfnComputeRun(ctx, h.commands, "iam", "DeleteLoginProfile", map[string]any{"UserName": name}); err != nil {
			return err
		}
	}
	return nil
}
func (h cfnIAMUser) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	u, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnIAMNamedResult(r.PhysicalID, cfnComputeValue(u.Arn))
	if err := cfnComputeRun(ctx, h.commands, "iam", "UpdateUser", map[string]any{"UserName": r.PhysicalID, "NewPath": cfnComputeDefault(r.Properties, "Path", "/")}); err != nil {
		return result, err
	}
	boundary := cfnComputeString(r.Properties, "PermissionsBoundary")
	if boundary != "" {
		err = cfnComputeRun(ctx, h.commands, "iam", "PutUserPermissionsBoundary", map[string]any{"UserName": r.PhysicalID, "PermissionsBoundary": boundary})
	} else if u.PermissionsBoundary != nil {
		err = cfnComputeRun(ctx, h.commands, "iam", "DeleteUserPermissionsBoundary", map[string]any{"UserName": r.PhysicalID})
	}
	if err != nil {
		return result, err
	}
	if err := h.configure(ctx, r, u); err != nil {
		return result, err
	}
	if err := cfnIAMUpdateTags(ctx, h.commands, r, "User", "UserName", r.PhysicalID, cfnIAMTags(u.Tags)); err != nil {
		return result, err
	}
	u, err = h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return result, err
	}
	return cfnIAMNamedResult(r.PhysicalID, cfnComputeValue(u.Arn)), nil
}
func (h cfnIAMUser) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnIAMContext(ctx, r)
	u, err := h.owned(ctx, r, cfnComputeName(r, "UserName", 64))
	if err != nil {
		return cfnComputeAbsent(err)
	}
	r.Previous = r.Properties
	r.Properties = cloudformation.Properties{}
	if err := h.configure(ctx, r, u); err != nil {
		return err
	}
	if u.PermissionsBoundary != nil {
		if err := cfnComputeRun(ctx, h.commands, "iam", "DeleteUserPermissionsBoundary", map[string]any{"UserName": cfnComputeValue(u.UserName)}); err != nil {
			return err
		}
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "iam", "DeleteUser", map[string]any{"UserName": cfnComputeValue(u.UserName)}))
}
func (h cfnIAMUser) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	u, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	name := cfnComputeValue(u.UserName)
	p, err := cfnIAMIdentityPolicies(ctx, h.commands, "User", name)
	if err != nil {
		return nil, err
	}
	p["UserName"] = name
	p["Path"] = cfnComputeValue(u.Path)
	p["Arn"] = cfnComputeValue(u.Arn)
	p["Tags"] = cfnIAMUserTags(u.Tags)
	if u.PermissionsBoundary != nil {
		p["PermissionsBoundary"] = cfnComputeValue(u.PermissionsBoundary.PermissionsBoundaryArn)
	}
	groups := []string{}
	in := map[string]any{"UserName": name}
	for {
		out, e := cfnComputeCall[api.ListGroupsForUserOutput](ctx, h.commands, "iam", "ListGroupsForUser", in)
		if e != nil {
			return nil, e
		}
		for _, g := range out.Groups {
			groups = append(groups, cfnComputeValue(g.GroupName))
		}
		marker := cfnComputeValue(out.Marker)
		if marker == "" {
			break
		}
		in["Marker"] = marker
	}
	p["Groups"] = groups
	profile, e := cfnComputeCall[api.GetLoginProfileOutput](ctx, h.commands, "iam", "GetLoginProfile", map[string]any{"UserName": name})
	if e != nil && !cfnComputeMissing(e) {
		return nil, e
	}
	if e == nil && profile.LoginProfile != nil {
		p["LoginProfile"] = map[string]any{"PasswordResetRequired": profile.LoginProfile.PasswordResetRequired != nil && bool(*profile.LoginProfile.PasswordResetRequired)}
	}
	return p, nil
}
func (h cfnIAMUser) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListUsersOutput](ctx, h.commands, "iam", "ListUsers", in)
		if err != nil {
			return nil, err
		}
		for _, u := range out.Users {
			rr := r
			rr.PhysicalID = cfnComputeValue(u.UserName)
			model, e := h.Read(ctx, rr)
			if e != nil {
				if !r.CloudControl {
					continue
				}
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
