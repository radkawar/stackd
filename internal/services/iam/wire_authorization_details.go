package iam

import (
	"cmp"
	"context"
	"slices"
	"strings"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func authorizationUserDetail(a *account, u *user) (iamapi.UserDetail, *awswire.Error) {
	base := wireUser(u, true)
	if base.Tags == nil {
		base.Tags = make(iamapi.TagListType, 0)
	}
	attached, err := authorizationAttachedPolicies(a, u.IdentityPolicies)
	if err != nil {
		return iamapi.UserDetail{}, err
	}
	groups := make(iamapi.GroupNameListType, 0)
	for _, g := range a.groups {
		if _, member := g.Members[strings.ToLower(u.UserName)]; member {
			groups = append(groups, iamapi.GroupNameType(g.GroupName))
		}
	}
	slices.Sort(groups)
	// Unlike GroupDetail and RoleDetail, AWS omits an empty user inline list.
	var inline iamapi.PolicyDetailListType
	if len(u.Inline) != 0 {
		inline = authorizationInlinePolicies(u.IdentityPolicies)
	}
	return iamapi.UserDetail{
		Arn: base.Arn, Path: base.Path, UserId: base.UserId, UserName: base.UserName, CreateDate: base.CreateDate,
		PermissionsBoundary: base.PermissionsBoundary, Tags: base.Tags, GroupList: groups,
		UserPolicyList: inline, AttachedManagedPolicies: attached,
	}, nil
}

func authorizationGroupDetail(a *account, g *group) (iamapi.GroupDetail, *awswire.Error) {
	base := wireGroup(g)
	attached, err := authorizationAttachedPolicies(a, g.IdentityPolicies)
	if err != nil {
		return iamapi.GroupDetail{}, err
	}
	return iamapi.GroupDetail{
		Arn: base.Arn, Path: base.Path, GroupId: base.GroupId, GroupName: base.GroupName, CreateDate: base.CreateDate,
		GroupPolicyList: authorizationInlinePolicies(g.IdentityPolicies), AttachedManagedPolicies: attached,
	}, nil
}

func (s *Service) authorizationRoleDetail(ctx context.Context, a *account, m awsctx.Metadata, r *role) (iamapi.RoleDetail, *awswire.Error) {
	base, err := s.generatedRole(ctx, m, r, "GetRole", a.currentTime)
	if err != nil {
		return iamapi.RoleDetail{}, err
	}
	if base.Tags == nil {
		base.Tags = make(iamapi.TagListType, 0)
	}
	attached, err := authorizationAttachedPolicies(a, r.IdentityPolicies)
	if err != nil {
		return iamapi.RoleDetail{}, err
	}
	out := iamapi.RoleDetail{
		Arn: base.Arn, Path: base.Path, RoleId: base.RoleId, RoleName: base.RoleName, CreateDate: base.CreateDate,
		AssumeRolePolicyDocument: base.AssumeRolePolicyDocument, RoleLastUsed: base.RoleLastUsed,
		PermissionsBoundary: base.PermissionsBoundary, Tags: base.Tags,
		RolePolicyList: authorizationInlinePolicies(r.IdentityPolicies), AttachedManagedPolicies: attached,
		InstanceProfileList: make(iamapi.InstanceProfileListType, 0),
	}
	for _, key := range sortedMapKeys(a.instanceProfiles) {
		profile := a.instanceProfiles[key]
		if profile.RoleId != r.RoleId {
			continue
		}
		wire, err := s.wireInstanceProfile(ctx, a, m, profile, false)
		if err != nil {
			return iamapi.RoleDetail{}, err
		}
		out.InstanceProfileList = append(out.InstanceProfileList, *wire)
	}
	return out, nil
}

func authorizationInlinePolicies(identity IdentityPolicies) iamapi.PolicyDetailListType {
	out := make(iamapi.PolicyDetailListType, 0, len(identity.Inline))
	for _, name := range sortedMapKeys(identity.Inline) {
		out = append(out, iamapi.PolicyDetail{
			PolicyName:     wirePointer(iamapi.PolicyNameType(name)),
			PolicyDocument: wirePointer(iamapi.PolicyDocumentType(encodedDocument(identity.Inline[name]))),
		})
	}
	return out
}

func authorizationAttachedPolicies(a *account, identity IdentityPolicies) (iamapi.AttachedPoliciesListType, *awswire.Error) {
	out := make(iamapi.AttachedPoliciesListType, 0, len(identity.Attached))
	for _, arn := range sortedMapKeys(identity.Attached) {
		p := a.policies[arn]
		if p == nil {
			return nil, authorizationReportFailure()
		}
		out = append(out, iamapi.AttachedPolicy{
			PolicyArn: wirePointer(iamapi.ArnType(p.Arn)), PolicyName: wirePointer(iamapi.PolicyNameType(p.PolicyName)),
		})
	}
	return out, nil
}

func authorizationPolicyDetail(p *policy) iamapi.ManagedPolicyDetail {
	out := iamapi.ManagedPolicyDetail{
		Arn: wirePointer(iamapi.ArnType(p.Arn)), Path: wirePointer(iamapi.PolicyPathType(p.Path)),
		PolicyId: wirePointer(iamapi.IdType(p.PolicyId)), PolicyName: wirePointer(iamapi.PolicyNameType(p.PolicyName)),
		DefaultVersionId:              wirePointer(iamapi.PolicyVersionIdType(p.DefaultVersionId)),
		AttachmentCount:               wirePointer(iamapi.AttachmentCountType(p.AttachmentCount)),
		PermissionsBoundaryUsageCount: wirePointer(iamapi.AttachmentCountType(p.PermissionsBoundaryUsageCount)),
		IsAttachable:                  wirePointer(iamapi.BooleanType(p.IsAttachable)), CreateDate: wirePointer(p.CreateDate), UpdateDate: wirePointer(p.UpdateDate),
		PolicyVersionList: make(iamapi.PolicyDocumentVersionListType, 0, len(p.Versions)),
	}
	// This report omits Description even though GetPolicy returns it. Versions
	// are newest first by IAM's monotonically increasing vN identifier, including
	// nondefault versions. Compare digit lengths to avoid integer overflow.
	ids := sortedMapKeys(p.Versions)
	slices.SortFunc(ids, func(a, b string) int {
		if order := cmp.Compare(len(b), len(a)); order != 0 {
			return order
		}
		return strings.Compare(b, a)
	})
	for _, id := range ids {
		version := p.Versions[id]
		out.PolicyVersionList = append(out.PolicyVersionList, *wirePolicyVersion(version, true))
	}
	return out
}
