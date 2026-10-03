package iam

import iamapi "stackd/internal/awsapi/iam"

func wirePointer[T any](v T) *T { return &v }

func wireUser(u *user, details bool) *iamapi.User {
	out := &iamapi.User{
		Arn: wirePointer(iamapi.ArnType(u.Arn)), Path: wirePointer(iamapi.PathType(u.Path)),
		UserId: wirePointer(iamapi.IdType(u.UserId)), UserName: wirePointer(iamapi.UserNameType(u.UserName)),
		CreateDate: wirePointer(u.CreateDate), PasswordLastUsed: u.PasswordLastUsed,
	}
	if details {
		out.Tags = wireTags(u.Tags)
		if u.PermissionsBoundary != nil {
			out.PermissionsBoundary = &iamapi.AttachedPermissionsBoundary{
				PermissionsBoundaryArn:  wirePointer(iamapi.ArnType(u.PermissionsBoundary.PermissionsBoundaryArn)),
				PermissionsBoundaryType: wirePointer(iamapi.PermissionsBoundaryAttachmentType(u.PermissionsBoundary.PermissionsBoundaryType)),
			}
		}
	}
	return out
}

func wireUsers(users []*user) iamapi.UserListType {
	out := make(iamapi.UserListType, 0, len(users))
	for _, user := range users {
		out = append(out, *wireUser(user, false))
	}
	return out
}

func wireGroup(g *group) *iamapi.Group {
	return &iamapi.Group{
		Arn: wirePointer(iamapi.ArnType(g.Arn)), Path: wirePointer(iamapi.PathType(g.Path)),
		GroupId: wirePointer(iamapi.IdType(g.GroupId)), GroupName: wirePointer(iamapi.GroupNameType(g.GroupName)),
		CreateDate: wirePointer(g.CreateDate),
	}
}

func wireGroups(groups []*group) iamapi.GroupListType {
	out := make(iamapi.GroupListType, 0, len(groups))
	for _, group := range groups {
		out = append(out, *wireGroup(group))
	}
	return out
}

func wireTags(tags []tag) iamapi.TagListType {
	if len(tags) == 0 {
		return nil
	}
	out := make(iamapi.TagListType, 0, len(tags))
	for _, tag := range tags {
		out = append(out, iamapi.Tag{Key: wirePointer(iamapi.TagKeyType(tag.Key)), Value: wirePointer(iamapi.TagValueType(tag.Value))})
	}
	return out
}

func wireMarker(p pagination) *iamapi.ResponseMarkerType {
	if p.Marker == "" {
		return nil
	}
	return wirePointer(iamapi.ResponseMarkerType(p.Marker))
}
