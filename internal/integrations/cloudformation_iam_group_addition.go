package integrations

import (
	"context"
	"fmt"
	"slices"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
	iamowner "stackd/internal/services/iam"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-usertogroupaddition.html
// A native group association claim identifies the aggregate, including Users=[].
type cfnIAMUserToGroupAddition struct{ commands StepFunctionsCommands }

func (h cfnIAMUserToGroupAddition) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "GroupName", "Users"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "GroupName", "Users"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "GroupName"); err != nil {
		return err
	}
	_, err := cfnComputeStringList(p, "Users")
	return err
}
func (h cfnIAMUserToGroupAddition) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}
func cfnIAMAdditionID(r cloudformation.ResourceRequest) string {
	if r.CloudControl && r.PhysicalID != "" {
		return r.PhysicalID
	}
	return cfnIAMPolicyOwner(r)
}
func (h cfnIAMUserToGroupAddition) group(ctx context.Context, r cloudformation.ResourceRequest, name string, claim, release bool) (*api.GetGroupOutput, map[string]string, []string, error) {
	owners := map[string]string{}
	claims := []string{}
	owner := iamowner.CloudFormationContext{Owner: cfnIAMAdditionID(r), MemberOwners: &owners, MembershipClaims: &claims, ClaimMembership: claim, ReleaseMembership: release}
	out, err := cfnComputeCall[api.GetGroupOutput](iamowner.WithCloudFormationContext(ctx, owner), h.commands, "iam", "GetGroup", map[string]any{"GroupName": name})
	return out, owners, claims, err
}
func (h cfnIAMUserToGroupAddition) member(ctx context.Context, r cloudformation.ResourceRequest, group, user string, remove bool) error {
	op := "AddUserToGroup"
	if remove {
		op = "RemoveUserFromGroup"
	}
	owner := iamowner.CloudFormationContext{Owner: cfnIAMAdditionID(r)}
	err := cfnComputeRun(iamowner.WithCloudFormationContext(ctx, owner), h.commands, "iam", op, map[string]any{"GroupName": group, "UserName": user})
	if remove {
		return cfnComputeAbsent(err)
	}
	return err
}
func (h cfnIAMUserToGroupAddition) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeString(r.Properties, "GroupName")
	out, _, _, err := h.group(ctx, r, name, true, false)
	if err != nil {
		return cfnIAMCreationFailure(ctx, r, h, err)
	}
	id := cfnIAMAdditionID(r)
	result := cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": cfnComputeValue(out.Group.GroupId)}}
	users, _ := cfnComputeStringList(r.Properties, "Users")
	for _, user := range users {
		if err := h.member(ctx, r, name, user, false); err != nil {
			return result, err
		}
	}
	return result, nil
}
func (h cfnIAMUserToGroupAddition) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	before, err := h.List(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	exists := false
	for _, row := range before {
		if row.Identifier == cfnIAMAdditionID(r) {
			exists = true
		}
	}
	if !exists {
		return cloudformation.ResourceResult{}, cfnIAMNotFound()
	}
	result, err := h.Create(ctx, r)
	if err != nil {
		return result, err
	}
	newGroup := cfnComputeString(r.Properties, "GroupName")
	desired, _ := cfnComputeStringList(r.Properties, "Users")
	for _, row := range before {
		if row.Identifier != cfnIAMAdditionID(r) {
			continue
		}
		oldGroup := cfnComputeString(row.Properties, "GroupName")
		old, _ := row.Properties["Users"].([]string)
		for _, user := range old {
			if oldGroup != newGroup || !slices.Contains(desired, user) {
				if err := h.member(ctx, r, oldGroup, user, true); err != nil {
					return result, err
				}
			}
		}
		if oldGroup != newGroup {
			if _, _, _, err := h.group(ctx, r, oldGroup, false, true); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}
func (h cfnIAMUserToGroupAddition) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	rows, err := h.List(ctx, r)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.Identifier != cfnIAMAdditionID(r) {
			continue
		}
		group := cfnComputeString(row.Properties, "GroupName")
		users, _ := row.Properties["Users"].([]string)
		for _, user := range users {
			if err := h.member(ctx, r, group, user, true); err != nil {
				return err
			}
		}
		if _, _, _, err := h.group(ctx, r, group, false, true); err != nil {
			return cfnComputeAbsent(err)
		}
	}
	return nil
}
func (h cfnIAMUserToGroupAddition) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	rows, err := h.List(ctx, r)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Identifier == cfnIAMAdditionID(r) {
			return row.Properties, nil
		}
	}
	return nil, cfnIAMNotFound()
}
func (h cfnIAMUserToGroupAddition) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	groups, err := cfnIAMIdentityNames(ctx, h.commands, "Group")
	if err != nil {
		return nil, err
	}
	var result []cloudformation.ResourceDescription
	for _, name := range groups {
		in := map[string]any{"GroupName": name}
		usersByOwner := map[string][]string{}
		claims := []string{}
		for {
			owners := map[string]string{}
			owner := iamowner.CloudFormationContext{Owner: cfnIAMAdditionID(r), MemberOwners: &owners, MembershipClaims: &claims}
			out, e := cfnComputeCall[api.GetGroupOutput](iamowner.WithCloudFormationContext(ctx, owner), h.commands, "iam", "GetGroup", in)
			if e != nil {
				return nil, e
			}
			for _, user := range out.Users {
				userName := cfnComputeValue(user.UserName)
				id := owners[strings.ToLower(userName)]
				if id != "" {
					usersByOwner[id] = append(usersByOwner[id], userName)
				}
			}
			marker := cfnComputeValue(out.Marker)
			if marker == "" {
				break
			}
			in["Marker"] = marker
		}
		for _, id := range claims {
			if !r.CloudControl && id != cfnIAMAdditionID(r) {
				continue
			}
			users := usersByOwner[id]
			if users == nil {
				users = []string{}
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"Id": id, "GroupName": name, "Users": users}})
		}
	}
	return result, nil
}
func (h cfnIAMUserToGroupAddition) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, _, _, err := h.group(ctx, r, cfnComputeString(p, "GroupName"), false, false)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if out.Group == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("IAM returned no group")
	}
	return cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID, Attributes: map[string]any{"Id": cfnComputeValue(out.Group.GroupId)}}, nil
}
