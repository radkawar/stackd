package iam

import (
	"context"
	"fmt"
	"strings"

	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func attachPolicy(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	request, _ := awsapi.FromContext(ctx)
	var kind, targetName, arn string
	switch in := request.Input.(type) {
	case *iamapi.AttachUserPolicyInput:
		kind, targetName = "User", inputString(in.UserName)
		arn = inputString(in.PolicyArn)
	case *iamapi.AttachGroupPolicyInput:
		kind, targetName = "Group", inputString(in.GroupName)
		arn = inputString(in.PolicyArn)
	case *iamapi.AttachRolePolicyInput:
		kind, targetName = "Role", inputString(in.RoleName)
		arn = inputString(in.PolicyArn)
	default:
		return nil, requestBindingFailure()
	}
	identity, _, err := findIdentity(a, kind, targetName)
	if err != nil {
		return nil, err
	}
	return &iamapi.Unit{}, attachIdentityPolicy(a, identity, kind, arn)
}

func attachIdentityPolicy(a *account, identity *identityPolicies, kind, arn string) *awswire.Error {
	p, err := findPolicyARN(a, arn)
	if err != nil {
		return err
	}
	if err := policyAttachmentError(p, kind); err != nil {
		return err
	}
	if _, ok := identity.Attached[p.Arn]; ok {
		return nil
	}
	if quota := attachedPolicyQuota(kind); len(identity.Attached) >= quota {
		return limit(fmt.Sprintf("Cannot attach more than %d managed policies to an IAM %s.", quota, strings.ToLower(kind)))
	}
	identity.Attached[p.Arn] = struct{}{}
	p.AttachmentCount++
	return nil
}

func detachPolicy(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	request, _ := awsapi.FromContext(ctx)
	var kind, targetName, arn string
	switch in := request.Input.(type) {
	case *iamapi.DetachUserPolicyInput:
		kind, targetName = "User", inputString(in.UserName)
		arn = inputString(in.PolicyArn)
	case *iamapi.DetachGroupPolicyInput:
		kind, targetName = "Group", inputString(in.GroupName)
		arn = inputString(in.PolicyArn)
	case *iamapi.DetachRolePolicyInput:
		kind, targetName = "Role", inputString(in.RoleName)
		arn = inputString(in.PolicyArn)
	default:
		return nil, requestBindingFailure()
	}
	identity, _, err := findIdentity(a, kind, targetName)
	if err != nil {
		return nil, err
	}
	p, err := findPolicyARN(a, arn)
	if err != nil {
		return nil, err
	}
	if _, ok := identity.Attached[p.Arn]; !ok {
		return nil, missing("policy attachment", p.Arn)
	}
	delete(identity.Attached, p.Arn)
	delete(identity.AttachedOwners, p.Arn)
	p.AttachmentCount--
	return &iamapi.Unit{}, nil
}

func listAttachedPolicies(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	request, _ := awsapi.FromContext(ctx)
	var kind, targetName, pathPrefix string
	switch in := request.Input.(type) {
	case *iamapi.ListAttachedUserPoliciesInput:
		kind, targetName = "User", inputString(in.UserName)
		pathPrefix = inputString(in.PathPrefix)
	case *iamapi.ListAttachedGroupPoliciesInput:
		kind, targetName = "Group", inputString(in.GroupName)
		pathPrefix = inputString(in.PathPrefix)
	case *iamapi.ListAttachedRolePoliciesInput:
		kind, targetName = "Role", inputString(in.RoleName)
		pathPrefix = inputString(in.PathPrefix)
	default:
		return nil, requestBindingFailure()
	}
	identity, _, err := findIdentity(a, kind, targetName)
	if err != nil {
		return nil, err
	}
	items := make(iamapi.AttachedPoliciesListType, 0, len(identity.Attached))
	for arn := range identity.Attached {
		p := a.policies[arn]
		if strings.HasPrefix(p.Path, pathPrefix) {
			items = append(items, iamapi.AttachedPolicy{PolicyName: wirePointer(iamapi.PolicyNameType(p.PolicyName)), PolicyArn: wirePointer(iamapi.ArnType(p.Arn))})
		}
	}
	items, paging, err := page(ctx, items, func(p iamapi.AttachedPolicy) string { return string(*p.PolicyName) }, m, request.Input)
	truncated, marker := wirePointer(iamapi.BooleanType(paging.IsTruncated)), wireMarker(paging)
	switch kind {
	case "User":
		return &iamapi.ListAttachedUserPoliciesOutput{AttachedPolicies: items, IsTruncated: truncated, Marker: marker}, err
	case "Group":
		return &iamapi.ListAttachedGroupPoliciesOutput{AttachedPolicies: items, IsTruncated: truncated, Marker: marker}, err
	default:
		return &iamapi.ListAttachedRolePoliciesOutput{AttachedPolicies: items, IsTruncated: truncated, Marker: marker}, err
	}
}

type policyEntity struct {
	kind string
	name string
	id   string
}

func listEntitiesForPolicy(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.ListEntitiesForPolicyInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	p, err := findPolicyARN(a, inputString(in.PolicyArn))
	if err != nil {
		return nil, err
	}
	filter := inputString(in.EntityFilter)
	usage := inputString(in.PolicyUsageFilter)
	match := func(kind, path string, identity identityPolicies, b *boundary) bool {
		if filter != "" && filter != kind {
			return false
		}
		if !strings.HasPrefix(path, inputString(in.PathPrefix)) {
			return false
		}
		_, attached := identity.Attached[p.Arn]
		return matchesPolicyUsage(usage, attached, b != nil && b.PermissionsBoundaryArn == p.Arn)
	}
	items := make([]policyEntity, 0)
	for _, u := range a.users {
		if match("User", u.Path, u.IdentityPolicies, u.PermissionsBoundary) {
			items = append(items, policyEntity{"User", u.UserName, u.UserId})
		}
	}
	for _, g := range a.groups {
		if match("Group", g.Path, g.IdentityPolicies, nil) {
			items = append(items, policyEntity{"Group", g.GroupName, g.GroupId})
		}
	}
	for _, r := range a.roles {
		if match("Role", r.Path, r.IdentityPolicies, r.PermissionsBoundary) {
			items = append(items, policyEntity{"Role", r.RoleName, r.RoleId})
		}
	}
	items, paging, err := page(ctx, items, func(e policyEntity) string { return e.kind + "/" + e.name }, m, in)
	if err != nil {
		return nil, err
	}
	result := &iamapi.ListEntitiesForPolicyOutput{
		IsTruncated: wirePointer(iamapi.BooleanType(paging.IsTruncated)), Marker: wireMarker(paging),
		PolicyUsers: make(iamapi.PolicyUserListType, 0), PolicyGroups: make(iamapi.PolicyGroupListType, 0), PolicyRoles: make(iamapi.PolicyRoleListType, 0),
	}
	for _, e := range items {
		switch e.kind {
		case "User":
			result.PolicyUsers = append(result.PolicyUsers, iamapi.PolicyUser{UserName: wirePointer(iamapi.UserNameType(e.name)), UserId: wirePointer(iamapi.IdType(e.id))})
		case "Group":
			result.PolicyGroups = append(result.PolicyGroups, iamapi.PolicyGroup{GroupName: wirePointer(iamapi.GroupNameType(e.name)), GroupId: wirePointer(iamapi.IdType(e.id))})
		case "Role":
			result.PolicyRoles = append(result.PolicyRoles, iamapi.PolicyRole{RoleName: wirePointer(iamapi.RoleNameType(e.name)), RoleId: wirePointer(iamapi.IdType(e.id))})
		}
	}
	return result, nil
}
