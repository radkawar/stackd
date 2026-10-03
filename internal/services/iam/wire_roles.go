package iam

import (
	"context"
	"time"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) generatedRole(ctx context.Context, m awsctx.Metadata, r *role, action string, now time.Time) (*iamapi.Role, *awswire.Error) {
	rendered, err := s.wireRole(ctx, m, r)
	if err != nil {
		return nil, err
	}
	out := &iamapi.Role{
		Arn: wirePointer(iamapi.ArnType(r.Arn)), Path: wirePointer(iamapi.PathType(r.Path)),
		RoleId: wirePointer(iamapi.IdType(r.RoleId)), RoleName: wirePointer(iamapi.RoleNameType(r.RoleName)),
		CreateDate: wirePointer(r.CreateDate), AssumeRolePolicyDocument: wirePointer(iamapi.PolicyDocumentType(rendered.AssumeRolePolicyDocument)),
	}
	if r.Description != "" && action != "CreateRole" && action != "AcquireRole" {
		out.Description = wirePointer(iamapi.RoleDescriptionType(r.Description))
	}
	if action == "GetRole" || action == "ListRoles" {
		out.MaxSessionDuration = wirePointer(iamapi.RoleMaxSessionDurationType(r.MaxSessionDuration))
	}
	if action == "CreateRole" || action == "GetRole" {
		out.Tags = wireTags(r.Tags)
		if r.PermissionsBoundary != nil {
			out.PermissionsBoundary = &iamapi.AttachedPermissionsBoundary{
				PermissionsBoundaryArn:  wirePointer(iamapi.ArnType(r.PermissionsBoundary.PermissionsBoundaryArn)),
				PermissionsBoundaryType: wirePointer(iamapi.PermissionsBoundaryAttachmentType(r.PermissionsBoundary.PermissionsBoundaryType)),
			}
		}
	}
	if action == "GetRole" {
		if source := r.SourceRoleTemplate; source != nil {
			out.SourceRoleTemplate = &iamapi.SourceRoleTemplate{TemplateArn: wirePointer(iamapi.ArnType(source.ARN)), TemplateMinorVersion: wirePointer(iamapi.IntegerType(source.MinorVersion))}
		}
		out.RoleLastUsed = &iamapi.RoleLastUsed{}
		if r.LastUsed.recorded() && r.LastUsed.Date.After(now.Add(-400*24*time.Hour)) {
			out.RoleLastUsed.LastUsedDate = wirePointer(r.LastUsed.Date)
			out.RoleLastUsed.Region = wirePointer(iamapi.StringType(r.LastUsed.Region))
		}
	}
	return out, nil
}
