package iam

import (
	"context"
	"strings"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) listInstanceProfiles(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.ListInstanceProfilesInput](ctx)
	if err != nil {
		return nil, err
	}
	path := inputString(input.PathPrefix)
	items := make([]*InstanceProfile, 0, len(a.instanceProfiles))
	for _, profile := range a.instanceProfiles {
		if strings.HasPrefix(profile.Path, path) {
			items = append(items, profile)
		}
	}
	wire, p, err := s.instanceProfilePage(ctx, a, m, input, items)
	return &iamapi.ListInstanceProfilesOutput{InstanceProfiles: wire, IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: instanceProfileMarker(p)}, err
}

func (s *Service) listInstanceProfilesForRole(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.ListInstanceProfilesForRoleInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findRole(a, inputString(input.RoleName))
	if err != nil {
		return nil, err
	}
	selection := *input
	selection.RoleName = wirePointer(iamapi.RoleNameType(r.RoleName))
	items := make([]*InstanceProfile, 0)
	for _, profile := range a.instanceProfiles {
		if profile.RoleId == r.RoleId {
			items = append(items, profile)
		}
	}
	wire, p, err := s.instanceProfilePage(ctx, a, m, &selection, items)
	return &iamapi.ListInstanceProfilesForRoleOutput{InstanceProfiles: wire, IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: instanceProfileMarker(p)}, err
}

func (s *Service) instanceProfilePage(ctx context.Context, a *account, m awsctx.Metadata, input paginationInput, items []*InstanceProfile) (iamapi.InstanceProfileListType, pagination, *awswire.Error) {
	items, p, err := page(ctx, items, func(profile *InstanceProfile) string { return profile.InstanceProfileName }, m, input)
	if err != nil {
		return nil, p, err
	}
	result := make(iamapi.InstanceProfileListType, 0, len(items))
	for _, profile := range items {
		wire, err := s.wireInstanceProfile(ctx, a, m, profile, false)
		if err != nil {
			return nil, p, err
		}
		result = append(result, *wire)
	}
	return result, p, nil
}

func instanceProfileMarker(p pagination) *iamapi.ResponseMarkerType {
	if p.Marker == "" {
		return nil
	}
	return wirePointer(iamapi.ResponseMarkerType(p.Marker))
}

func (s *Service) wireInstanceProfile(ctx context.Context, a *account, m awsctx.Metadata, profile *InstanceProfile, includeTags bool) (*iamapi.InstanceProfile, *awswire.Error) {
	result := &iamapi.InstanceProfile{
		Path:                wirePointer(iamapi.PathType(profile.Path)),
		InstanceProfileName: wirePointer(iamapi.InstanceProfileNameType(profile.InstanceProfileName)),
		InstanceProfileId:   wirePointer(iamapi.IdType(profile.InstanceProfileId)),
		Arn:                 wirePointer(iamapi.ArnType(profile.Arn)),
		CreateDate:          wirePointer(profile.CreateDate),
		Roles:               make(iamapi.RoleListType, 0),
	}
	if includeTags {
		result.Tags = wireInstanceProfileTags(profile.Tags)
	}
	if profile.RoleId == "" {
		return result, nil
	}
	for _, r := range a.roles {
		if r.RoleId != profile.RoleId {
			continue
		}
		wire, err := s.wireRole(ctx, m, r)
		if err != nil {
			return nil, err
		}
		result.Roles = append(result.Roles, iamapi.Role{
			Arn:                      wirePointer(iamapi.ArnType(r.Arn)),
			RoleName:                 wirePointer(iamapi.RoleNameType(r.RoleName)),
			RoleId:                   wirePointer(iamapi.IdType(r.RoleId)),
			Path:                     wirePointer(iamapi.PathType(r.Path)),
			CreateDate:               wirePointer(r.CreateDate),
			AssumeRolePolicyDocument: wirePointer(iamapi.PolicyDocumentType(wire.AssumeRolePolicyDocument)),
		})
		return result, nil
	}
	return nil, &awswire.Error{Code: "ServiceFailure", Message: "Instance profile references a missing role.", StatusCode: 500}
}
