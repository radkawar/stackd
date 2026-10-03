package cognitoidp

import (
	"errors"

	api "stackd/internal/awsapi/cognitoidp"
)

func registerGroups(s *Service) {
	register(s, "CreateGroup", s.createGroup)
	register(s, "GetGroup", s.getGroup)
	register(s, "UpdateGroup", s.updateGroup)
	register(s, "DeleteGroup", s.deleteGroup)
	register(s, "ListGroups", s.listGroups)
	register(s, "AdminAddUserToGroup", s.adminAddUserToGroup)
	register(s, "AdminRemoveUserFromGroup", s.adminRemoveUserFromGroup)
	register(s, "AdminListGroupsForUser", s.adminListGroupsForUser)
	register(s, "ListUsersInGroup", s.listUsersInGroup)
}

func adminGroup(r Reader, pool PoolRecord, name string) (GroupRecord, error) {
	group, err := r.Group(GroupKey{PoolKey: pool.Key, Name: name})
	if errors.Is(err, ErrNotFound) {
		return GroupRecord{}, failure("ResourceNotFoundException", "Group not found.")
	}
	return group, err
}

func (s *Service) createGroup(tx Transaction, in *api.CreateGroupInput) (*api.CreateGroupOutput, error) {
	pool, err := s.adminPool(tx, "CreateGroup", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	if in.RoleArn != nil {
		if err := s.authorize(tx, "iam:PassRole", value(in.RoleArn), nil); err != nil {
			return nil, err
		}
	}
	key := GroupKey{PoolKey: pool.Key, Name: value(in.GroupName)}
	if _, err = tx.Group(key); err == nil {
		return nil, failure("GroupExistsException", "A group with the name already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := s.clock.Now()
	group := GroupRecord{Key: key, Data: api.GroupType{
		GroupName: in.GroupName, UserPoolId: in.UserPoolId,
		Description: in.Description, RoleArn: in.RoleArn, Precedence: in.Precedence,
		CreationDate: &now, LastModifiedDate: &now,
	}}
	if err = tx.PutGroup(group); err != nil {
		return nil, err
	}
	return &api.CreateGroupOutput{Group: &group.Data}, nil
}

func (s *Service) getGroup(tx Transaction, in *api.GetGroupInput) (*api.GetGroupOutput, error) {
	pool, err := s.adminPool(tx, "GetGroup", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	group, err := adminGroup(tx, pool, value(in.GroupName))
	if err != nil {
		return nil, err
	}
	return &api.GetGroupOutput{Group: &group.Data}, nil
}

func (s *Service) updateGroup(tx Transaction, in *api.UpdateGroupInput) (*api.UpdateGroupOutput, error) {
	pool, err := s.adminPool(tx, "UpdateGroup", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	if in.RoleArn != nil {
		if err := s.authorize(tx, "iam:PassRole", value(in.RoleArn), nil); err != nil {
			return nil, err
		}
	}
	group, err := adminGroup(tx, pool, value(in.GroupName))
	if err != nil {
		return nil, err
	}
	// Native empty descriptions and omitted/null optional fields leave the
	// existing configuration and modification timestamp untouched.
	updated := false
	if value(in.Description) != "" {
		group.Data.Description = in.Description
		updated = true
	}
	if in.RoleArn != nil {
		group.Data.RoleArn = in.RoleArn
		updated = true
	}
	if in.Precedence != nil {
		group.Data.Precedence = in.Precedence
		updated = true
	}
	if updated {
		now := s.clock.Now()
		group.Data.LastModifiedDate = &now
		if err = tx.PutGroup(group); err != nil {
			return nil, err
		}
	}
	return &api.UpdateGroupOutput{Group: &group.Data}, nil
}

func (s *Service) deleteGroup(tx Transaction, in *api.DeleteGroupInput) (*api.DeleteGroupOutput, error) {
	pool, err := s.adminPool(tx, "DeleteGroup", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	group, err := adminGroup(tx, pool, value(in.GroupName))
	if err != nil {
		return nil, err
	}
	if err = tx.DeleteGroup(group.Key); err != nil {
		return nil, err
	}
	return &api.DeleteGroupOutput{}, nil
}

func (s *Service) adminAddUserToGroup(tx Transaction, in *api.AdminAddUserToGroupInput) (*api.AdminAddUserToGroupOutput, error) {
	pool, err := s.adminPool(tx, "AdminAddUserToGroup", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	// Resolve first: native missing-group failures still attribute the known
	// user, and membership always retains the canonical username, not an alias.
	user, err := resolveUser(tx, pool, value(in.Username))
	if err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	group, err := adminGroup(tx, pool, value(in.GroupName))
	if err != nil {
		return nil, err
	}
	if err = tx.AddGroupUser(group.Key, user.Key.Username); err != nil {
		return nil, err
	}
	return &api.AdminAddUserToGroupOutput{}, nil
}

func (s *Service) adminRemoveUserFromGroup(tx Transaction, in *api.AdminRemoveUserFromGroupInput) (*api.AdminRemoveUserFromGroupOutput, error) {
	pool, err := s.adminPool(tx, "AdminRemoveUserFromGroup", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	user, err := resolveUser(tx, pool, value(in.Username))
	if err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	// A missing group is also an absent membership, but a missing user fails.
	key := GroupKey{PoolKey: pool.Key, Name: value(in.GroupName)}
	if err = tx.RemoveGroupUser(key, user.Key.Username); err != nil {
		return nil, err
	}
	return &api.AdminRemoveUserFromGroupOutput{}, nil
}

// The shared Smithy limit type permits zero, but native group listings reject it.
// This service constraint must not be inferred from the model's lower bound.
func groupPageLimit(requested *api.QueryLimitType) (int, error) {
	limit := 60
	if requested != nil {
		limit = int(*requested)
	}
	if limit < 1 || limit > 60 {
		return 0, failure("InvalidParameterException", "Limit must be between 1 and 60.")
	}
	return limit, nil
}

// Repository collections are ordered by name; the shared cursor is scoped to
// the operation, pool and, for memberships, the canonical user or group.
func groupPage(groups []GroupRecord, binding, cursor string, limit int) (api.GroupListType, *api.PaginationKey) {
	out := make(api.GroupListType, 0, min(limit, len(groups)))
	for _, group := range groups {
		if group.Key.Name <= cursor {
			continue
		}
		if len(out) == limit {
			return out, str[api.PaginationKey](nextPage(binding, value(out[len(out)-1].GroupName)))
		}
		out = append(out, group.Data)
	}
	return out, nil
}

func (s *Service) listGroups(tx Transaction, in *api.ListGroupsInput) (*api.ListGroupsOutput, error) {
	pool, err := s.adminPool(tx, "ListGroups", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	limit, err := groupPageLimit(in.Limit)
	if err != nil {
		return nil, err
	}
	binding := "groups:" + pool.Key.ARN()
	cursor, err := pageCursor(value(in.NextToken), binding)
	if err != nil {
		return nil, err
	}
	groups, err := tx.Groups(pool.Key)
	if err != nil {
		return nil, err
	}
	out := &api.ListGroupsOutput{}
	out.Groups, out.NextToken = groupPage(groups, binding, cursor, limit)
	return out, nil
}

func (s *Service) adminListGroupsForUser(tx Transaction, in *api.AdminListGroupsForUserInput) (*api.AdminListGroupsForUserOutput, error) {
	pool, err := s.adminPool(tx, "AdminListGroupsForUser", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	user, err := resolveUser(tx, pool, value(in.Username))
	if err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	limit, err := groupPageLimit(in.Limit)
	if err != nil {
		return nil, err
	}
	binding := "user-groups:" + pool.Key.ARN() + ":" + user.Key.Username
	cursor, err := pageCursor(value(in.NextToken), binding)
	if err != nil {
		return nil, err
	}
	groups, err := tx.GroupsForUser(user.Key)
	if err != nil {
		return nil, err
	}
	out := &api.AdminListGroupsForUserOutput{}
	out.Groups, out.NextToken = groupPage(groups, binding, cursor, limit)
	return out, nil
}

func (s *Service) listUsersInGroup(tx Transaction, in *api.ListUsersInGroupInput) (*api.ListUsersInGroupOutput, error) {
	pool, err := s.adminPool(tx, "ListUsersInGroup", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	group, err := adminGroup(tx, pool, value(in.GroupName))
	if err != nil {
		return nil, err
	}
	limit, err := groupPageLimit(in.Limit)
	if err != nil {
		return nil, err
	}
	binding := "group-users:" + pool.Key.ARN() + ":" + group.Key.Name
	cursor, err := pageCursor(value(in.NextToken), binding)
	if err != nil {
		return nil, err
	}
	users, err := tx.UsersInGroup(group.Key)
	if err != nil {
		return nil, err
	}
	out := &api.ListUsersInGroupOutput{Users: make(api.UsersListType, 0, min(limit, len(users)))}
	for _, user := range users {
		if user.Key.Username <= cursor {
			continue
		}
		if len(out.Users) == limit {
			out.NextToken = str[api.PaginationKey](nextPage(binding, value(out.Users[len(out.Users)-1].Username)))
			break
		}
		out.Users = append(out.Users, user.Data)
	}
	return out, nil
}
