package iam

import (
	"context"
	"strings"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func findGroup(a *account, name string) (*group, *awswire.Error) {
	g := a.groups[strings.ToLower(name)]
	if g == nil {
		return nil, missing("group", name)
	}
	return g, nil
}

func createGroup(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.CreateGroupInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	name := inputString(in.GroupName)
	path := defaultPath(inputString(in.Path))
	key := strings.ToLower(name)
	if a.groups[key] != nil {
		return nil, duplicate("Group", name)
	}
	if len(a.groups) >= maxGroups {
		return nil, limit("IAM group quota exceeded.")
	}
	g := &group{Path: path, GroupName: name, GroupId: newID("AGPA"), Arn: resourceARN(m, "group", path, name), CreateDate: a.currentTime, IdentityPolicies: newIdentityPolicies(), Members: make(map[string]struct{})}
	a.groups[key] = g
	return &iamapi.CreateGroupOutput{Group: wireGroup(g)}, nil
}

func getGroup(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.GetGroupInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	g, err := findGroup(a, inputString(in.GroupName))
	if err != nil {
		return nil, err
	}
	items := make([]*user, 0, len(g.Members))
	for key := range g.Members {
		items = append(items, a.users[key])
	}
	items, p, err := page(ctx, items, func(u *user) string { return u.UserName }, m, in)
	return &iamapi.GetGroupOutput{Group: wireGroup(g), Users: wireUsers(items), IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: wireMarker(p)}, err
}

func listGroups(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.ListGroupsInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	items := make([]*group, 0, len(a.groups))
	for _, g := range a.groups {
		if strings.HasPrefix(g.Path, inputString(in.PathPrefix)) {
			items = append(items, g)
		}
	}
	items, p, err := page(ctx, items, func(g *group) string { return g.GroupName }, m, in)
	return &iamapi.ListGroupsOutput{Groups: wireGroups(items), IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: wireMarker(p)}, err
}

func updateGroup(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.UpdateGroupInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	g, err := findGroup(a, inputString(in.GroupName))
	if err != nil {
		return nil, err
	}
	name, path := g.GroupName, g.Path
	if in.NewGroupName != nil {
		name = inputString(in.NewGroupName)
		if existing := a.groups[strings.ToLower(name)]; existing != nil && existing != g {
			return nil, duplicate("Group", name)
		}
	}
	if in.NewPath != nil {
		path = inputString(in.NewPath)
	}
	delete(a.groups, strings.ToLower(g.GroupName))
	g.GroupName, g.Path, g.Arn = name, path, resourceARN(m, "group", path, name)
	a.groups[strings.ToLower(name)] = g
	return &iamapi.UpdateGroupOutput{}, nil
}

func deleteGroup(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.DeleteGroupInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	g, err := findGroup(a, inputString(in.GroupName))
	if err != nil {
		return nil, err
	}
	if len(g.Members) > 0 || len(g.Inline) > 0 || len(g.Attached) > 0 {
		return nil, conflict("Cannot delete group with users or policies.")
	}
	delete(a.groups, strings.ToLower(g.GroupName))
	return &iamapi.DeleteGroupOutput{}, nil
}

func addUserToGroup(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.AddUserToGroupInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	g, err := findGroup(a, inputString(in.GroupName))
	if err != nil {
		return nil, err
	}
	u, err := findUser(a, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(u.UserName)
	if _, ok := g.Members[key]; ok {
		return &iamapi.AddUserToGroupOutput{}, nil
	}
	count := 0
	for _, candidate := range a.groups {
		if _, ok := candidate.Members[key]; ok {
			count++
		}
	}
	if count >= maxGroupsPerUser {
		return nil, limit("Cannot add a user to more than 10 groups.")
	}
	g.Members[key] = struct{}{}
	return &iamapi.AddUserToGroupOutput{}, nil
}

func removeUserFromGroup(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.RemoveUserFromGroupInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	g, err := findGroup(a, inputString(in.GroupName))
	if err != nil {
		return nil, err
	}
	u, err := findUser(a, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(u.UserName)
	delete(g.Members, key)
	return &iamapi.RemoveUserFromGroupOutput{}, nil
}

func listGroupsForUser(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.ListGroupsForUserInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	u, err := findUser(a, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	items := make([]*group, 0)
	for _, g := range a.groups {
		if _, ok := g.Members[strings.ToLower(u.UserName)]; ok {
			items = append(items, g)
		}
	}
	items, p, err := page(ctx, items, func(g *group) string { return g.GroupName }, m, in)
	return &iamapi.ListGroupsForUserOutput{Groups: wireGroups(items), IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: wireMarker(p)}, err
}
