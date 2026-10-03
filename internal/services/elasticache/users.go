package elasticache

import (
	"context"
	"errors"
	"slices"
	engine "stackd/engine/valkey"
	api "stackd/internal/awsapi/elasticache"
	"strings"
)

func userRecord(r Reader, k Key) (User, error) {
	v, err := r.User(k)
	if errors.Is(err, ErrNotFound) && k.Name == "default" {
		return User{Key: k, Name: "default", Engine: "redis", AccessString: "on ~* +@all", Status: "active", NoPassword: true}, nil
	}
	return v, err
}

func (s *Service) loadUser(ctx context.Context, r Reader, action, id string) (User, error) {
	k, e := resourceKey(ctx, "user", id)
	if e != nil {
		return User{}, e
	}
	v, e := userRecord(r, k)
	if errors.Is(e, ErrNotFound) {
		e = notFound("user")
	}
	if e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}
func (s *Service) loadUserGroup(ctx context.Context, r Reader, action, id string) (UserGroup, error) {
	k, e := resourceKey(ctx, "usergroup", id)
	if e != nil {
		return UserGroup{}, e
	}
	v, e := r.UserGroup(k)
	if errors.Is(e, ErrNotFound) {
		e = notFound("usergroup")
	}
	if e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}
func authentication(v *User, mode *api.AuthenticationMode, noPassword *api.BooleanOptional, passwords api.PasswordListInput, required bool) error {
	if mode != nil {
		if noPassword != nil || len(passwords) > 0 {
			return unsupported("AuthenticationMode cannot be combined with password parameters.")
		}
		switch value(mode.Type) {
		case "password":
			passwords = mode.Passwords
		case string(api.InputAuthenticationTypeNO_PASSWORD):
			if len(mode.Passwords) > 0 {
				return unsupported("no-password authentication cannot include passwords.")
			}
			noPassword = new(api.BooleanOptional(true))
		case "iam":
			return unsupported("IAM engine authentication requires a native authentication gateway.")
		default:
			return failure("InvalidParameterValue", "Invalid AuthenticationMode.")
		}
	}
	if boolean(noPassword) {
		if len(passwords) > 0 {
			return unsupported("NoPasswordRequired cannot be combined with passwords.")
		}
		v.NoPassword = true
		v.PasswordHashes = nil
	} else if len(passwords) > 0 {
		if len(passwords) > 2 {
			return failure("InvalidParameterValue", "At most two passwords are allowed.")
		}
		v.NoPassword = false
		v.PasswordHashes = nil
		for _, p := range passwords {
			if len(p) < 16 || len(p) > 128 {
				return failure("InvalidParameterValue", "Passwords must contain 16 to 128 characters.")
			}
			h := hashPassword(string(p))
			if slices.Contains(v.PasswordHashes, h) {
				return failure("InvalidParameterValue", "Passwords must be distinct.")
			}
			v.PasswordHashes = append(v.PasswordHashes, h)
		}
	} else if required || noPassword != nil || mode != nil {
		return failure("InvalidParameterValue", "Password authentication requires a password.")
	}
	return nil
}
func validateUser(v User) error {
	if v.Name == "stackd-controller" || v.Name == "" {
		return failure("InvalidParameterValue", "Invalid reserved user name.")
	}
	if strings.TrimSpace(v.AccessString) == "" {
		return failure("InvalidParameterValue", "AccessString must not be empty.")
	}
	if e := engine.ValidateUsers([]engine.User{{Name: v.Name, AccessString: v.AccessString, PasswordHashes: v.PasswordHashes, NoPassword: v.NoPassword}}); e != nil {
		return failure("InvalidParameterValue", e.Error())
	}
	return nil
}
func (s *Service) createUser(ctx context.Context, tx Transaction, in *api.CreateUserMessage) (*api.User, error) {
	k, e := resourceKey(ctx, "user", value(in.UserId))
	if e != nil {
		return nil, e
	}
	if k.Name == "default" {
		return nil, existsError("user")
	}
	name, _, e := engineVersion(value(in.Engine), "")
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateUser", k, nil, tags); e != nil {
		return nil, e
	}
	if _, e = tx.User(k); e == nil {
		return nil, existsError(k.Kind)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	v := User{Key: k, Name: value(in.UserName), Engine: name, AccessString: value(in.AccessString), Status: "active", Tags: tags}
	if e = authentication(&v, in.AuthenticationMode, in.NoPasswordRequired, in.Passwords, true); e != nil {
		return nil, e
	}
	if e = validateUser(v); e != nil {
		return nil, e
	}
	if e = tx.PutUser(v); e != nil {
		return nil, e
	}
	return s.userOutput(tx, v)
}
func (s *Service) modifyUser(ctx context.Context, tx Transaction, in *api.ModifyUserMessage) (*api.User, error) {
	v, e := s.loadUser(ctx, tx, "ModifyUser", value(in.UserId))
	if e != nil {
		return nil, e
	}
	if v.Status != "active" {
		return nil, stateError("user")
	}
	if in.Engine != nil && value(in.Engine) != v.Engine {
		return nil, unsupported("Changing user engines is not supported.")
	}
	if in.AccessString != nil && in.AppendAccessString != nil {
		return nil, unsupported("AccessString and AppendAccessString cannot be combined.")
	}
	if in.AccessString != nil {
		v.AccessString = value(in.AccessString)
	}
	if in.AppendAccessString != nil {
		v.AccessString += " " + value(in.AppendAccessString)
	}
	if e = authentication(&v, in.AuthenticationMode, in.NoPasswordRequired, in.Passwords, false); e != nil {
		return nil, e
	}
	if e = validateUser(v); e != nil {
		return nil, e
	}
	groups, e := tx.UserGroups(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	attached := false
	for _, g := range groups {
		if slices.Contains(g.UserIDs, v.Key.Name) {
			changed, e := s.applyUserGroup(tx, g)
			if e != nil {
				return nil, e
			}
			attached = attached || changed
		}
	}
	if attached {
		v.Status = "modifying"
	}
	if e = tx.PutUser(v); e != nil {
		return nil, e
	}
	return s.userOutput(tx, v)
}
func (s *Service) deleteUser(ctx context.Context, tx Transaction, in *api.DeleteUserMessage) (*api.User, error) {
	v, e := s.loadUser(ctx, tx, "DeleteUser", value(in.UserId))
	if e != nil {
		return nil, e
	}
	if v.Key.Name == "default" {
		return nil, failure("InvalidParameterValue", "The service-provided default user cannot be deleted.")
	}
	if v.Status != "active" {
		return nil, stateError("user")
	}
	groups, e := tx.UserGroups(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	attached := false
	for _, g := range groups {
		if !slices.Contains(g.UserIDs, v.Key.Name) {
			continue
		}
		if v.Name == "default" {
			return nil, failure("DefaultUserAssociatedToUserGroup", "A default user cannot be deleted while it belongs to a user group.")
		}
		if g.Status != "active" {
			return nil, stateError("usergroup")
		}
		changed, err := s.applyUserGroup(tx, g)
		if err != nil {
			return nil, err
		}
		if changed {
			attached = true
			g.Status = "modifying"
		} else {
			g.UserIDs = slices.DeleteFunc(g.UserIDs, func(id string) bool { return id == v.Key.Name })
		}
		if e = tx.PutUserGroup(g); e != nil {
			return nil, e
		}
	}
	out, e := s.userOutput(tx, v)
	if e != nil {
		return nil, e
	}
	out.Status = new(api.String("deleting"))
	if attached {
		v.Status = "deleting"
		return out, tx.PutUser(v)
	}
	return out, tx.DeleteUser(v.Key)
}
func (s *Service) validateMembers(ctx context.Context, r Reader, action string, g UserGroup) error {
	if len(g.UserIDs) == 0 {
		return failure("DefaultUserRequired", "A user group must include a user named default.")
	}
	names := map[string]bool{}
	for _, id := range g.UserIDs {
		u, e := s.loadUser(ctx, r, action, id)
		if e != nil {
			return e
		}
		if u.Status != "active" {
			return stateError("user")
		}
		if u.Engine != g.Engine {
			return unsupported("User and user group engines must match.")
		}
		if names[u.Name] {
			return failure("DuplicateUserName", "User names must be unique within a group.")
		}
		names[u.Name] = true
	}
	if !names["default"] {
		return failure("DefaultUserRequired", "A user group must include a user named default.")
	}
	return nil
}
func (s *Service) validateAttachment(ctx context.Context, r Reader, action string, v Cluster) error {
	g, e := s.loadUserGroup(ctx, r, action, v.UserGroup)
	if e != nil {
		return e
	}
	if g.Status != "active" {
		return stateError("usergroup")
	}
	if g.Engine != v.Engine {
		return unsupported("User group and cache engines must match.")
	}
	return s.validateMembers(ctx, r, action, g)
}
func (s *Service) createUserGroup(ctx context.Context, tx Transaction, in *api.CreateUserGroupMessage) (*api.UserGroup, error) {
	k, e := resourceKey(ctx, "usergroup", value(in.UserGroupId))
	if e != nil {
		return nil, e
	}
	name, _, e := engineVersion(value(in.Engine), "")
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateUserGroup", k, nil, tags); e != nil {
		return nil, e
	}
	if _, e = tx.UserGroup(k); e == nil {
		return nil, existsError(k.Kind)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	g := UserGroup{Key: k, Engine: name, Status: "active", Tags: tags}
	for _, id := range in.UserIds {
		g.UserIDs = append(g.UserIDs, strings.ToLower(string(id)))
	}
	slices.Sort(g.UserIDs)
	if e = s.validateMembers(ctx, tx, "CreateUserGroup", g); e != nil {
		return nil, e
	}
	if e = tx.PutUserGroup(g); e != nil {
		return nil, e
	}
	return s.userGroupOutput(tx, g)
}
func (s *Service) modifyUserGroup(ctx context.Context, tx Transaction, in *api.ModifyUserGroupMessage) (*api.UserGroup, error) {
	g, e := s.loadUserGroup(ctx, tx, "ModifyUserGroup", value(in.UserGroupId))
	if e != nil {
		return nil, e
	}
	if g.Status != "active" {
		return nil, stateError("usergroup")
	}
	if in.Engine != nil && value(in.Engine) != g.Engine {
		return nil, unsupported("Changing the group engine is not supported.")
	}
	for _, id := range in.UserIdsToRemove {
		index := slices.Index(g.UserIDs, string(id))
		if index < 0 {
			return nil, notFound("user")
		}
		g.UserIDs = slices.Delete(g.UserIDs, index, index+1)
	}
	for _, id := range in.UserIdsToAdd {
		if slices.Contains(g.UserIDs, string(id)) {
			return nil, failure("InvalidParameterValue", "User already belongs to this group.")
		}
		g.UserIDs = append(g.UserIDs, string(id))
	}
	slices.Sort(g.UserIDs)
	if e = s.validateMembers(ctx, tx, "ModifyUserGroup", g); e != nil {
		return nil, e
	}
	changed, e := s.applyUserGroup(tx, g)
	if e != nil {
		return nil, e
	}
	if changed {
		g.Status = "modifying"
	}
	if e = tx.PutUserGroup(g); e != nil {
		return nil, e
	}
	return s.userGroupOutput(tx, g)
}
func (s *Service) deleteUserGroup(ctx context.Context, tx Transaction, in *api.DeleteUserGroupMessage) (*api.UserGroup, error) {
	g, e := s.loadUserGroup(ctx, tx, "DeleteUserGroup", value(in.UserGroupId))
	if e != nil {
		return nil, e
	}
	all, e := tx.Clusters(g.Key.Scope)
	if e != nil {
		return nil, e
	}
	for _, v := range all {
		if v.UserGroup == g.Key.Name {
			return nil, stateError("usergroup")
		}
	}
	out, e := s.userGroupOutput(tx, g)
	if e != nil {
		return nil, e
	}
	out.Status = new(api.String("deleting"))
	return out, tx.DeleteUserGroup(g.Key)
}
func (s *Service) applyUserGroup(tx Transaction, g UserGroup) (bool, error) {
	all, e := tx.Clusters(g.Key.Scope)
	if e != nil {
		return false, e
	}
	changed := false
	for _, v := range all {
		if v.UserGroup != g.Key.Name {
			continue
		}
		if v.Status != "available" {
			return false, stateError(v.Key.Kind)
		}
		if e = s.markCluster(tx, v, "acl", "modifying"); e != nil {
			return false, e
		}
		changed = true
	}
	return changed, nil
}
func (s *Service) userOutput(r Reader, v User) (*api.User, error) {
	kind := api.AuthenticationTypePASSWORD
	if v.NoPassword {
		kind = api.AuthenticationTypeNO_PASSWORD
	}
	minimum := "6.0"
	if v.Engine == "valkey" {
		minimum = "7.2"
	}
	out := &api.User{ARN: new(api.String(v.Key.ARN())), UserId: new(api.String(v.Key.Name)), UserName: new(api.String(v.Name)), Engine: new(api.EngineType(v.Engine)), MinimumEngineVersion: new(api.String(minimum)), AccessString: new(api.String(v.AccessString)), Status: new(api.String(v.Status)), UserGroupIds: api.UserGroupIdList{}, Authentication: &api.Authentication{Type: &kind, PasswordCount: new(api.IntegerOptional(len(v.PasswordHashes)))}}
	if v.NoPassword {
		out.Authentication.PasswordCount = nil
	}
	groups, e := r.UserGroups(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	for _, g := range groups {
		if slices.Contains(g.UserIDs, v.Key.Name) {
			out.UserGroupIds = append(out.UserGroupIds, api.UserGroupId(g.Key.Name))
		}
	}
	return out, nil
}
func (s *Service) userGroupOutput(r Reader, g UserGroup) (*api.UserGroup, error) {
	out := &api.UserGroup{ARN: new(api.String(g.Key.ARN())), UserGroupId: new(api.String(g.Key.Name)), Engine: new(api.EngineType(g.Engine)), Status: new(api.String(g.Status))}
	for _, id := range g.UserIDs {
		out.UserIds = append(out.UserIds, api.UserId(id))
	}
	clusters, e := r.Clusters(g.Key.Scope)
	if e != nil {
		return nil, e
	}
	for _, v := range clusters {
		if v.UserGroup == g.Key.Name {
			out.ReplicationGroups = append(out.ReplicationGroups, api.String(v.Key.Name))
		}
	}
	return out, nil
}
func (s *Service) describeUsers(ctx context.Context, tx Transaction, in *api.DescribeUsersMessage) (*api.DescribeUsersResult, error) {
	if len(in.Filters) > 0 {
		return nil, unsupported("DescribeUsers Filters are not supported.")
	}
	var all []User
	var e error
	if in.UserId != nil {
		v, err := s.loadUser(ctx, tx, "DescribeUsers", value(in.UserId))
		e = err
		all = []User{v}
	} else {
		e = s.authorize(ctx, "DescribeUsers", Key{}, nil, nil)
		if e == nil {
			all, e = tx.Users(scopeFor(ctx))
			if e == nil {
				hasDefault := slices.ContainsFunc(all, func(u User) bool { return u.Key.Name == "default" })
				if !hasDefault {
					v, err := userRecord(tx, Key{Scope: scopeFor(ctx), Kind: "user", Name: "default"})
					if err != nil {
						return nil, err
					}
					all = append(all, v)
					slices.SortFunc(all, func(a, b User) int { return strings.Compare(a.Key.Name, b.Key.Name) })
				}
			}
		}
	}
	if e != nil {
		return nil, e
	}
	filtered := all[:0]
	for _, u := range all {
		if in.Engine == nil || value(in.Engine) == u.Engine {
			filtered = append(filtered, u)
		}
	}
	selected := filtered
	var next *api.String
	if in.UserId == nil {
		selected, next, e = page(ctx, "DescribeUsers", value(in.Engine), filtered, in.Marker, in.MaxRecords, func(v User) string { return v.Key.Name })
		if e != nil {
			return nil, e
		}
	}
	out := &api.DescribeUsersResult{Marker: next, Users: api.UserList{}}
	for _, v := range selected {
		u, e := s.userOutput(tx, v)
		if e != nil {
			return nil, e
		}
		out.Users = append(out.Users, *u)
	}
	return out, nil
}
func (s *Service) describeUserGroups(ctx context.Context, tx Transaction, in *api.DescribeUserGroupsMessage) (*api.DescribeUserGroupsResult, error) {
	var all []UserGroup
	var e error
	if in.UserGroupId != nil {
		v, err := s.loadUserGroup(ctx, tx, "DescribeUserGroups", value(in.UserGroupId))
		e = err
		all = []UserGroup{v}
	} else {
		e = s.authorize(ctx, "DescribeUserGroups", Key{}, nil, nil)
		if e == nil {
			all, e = tx.UserGroups(scopeFor(ctx))
		}
	}
	if e != nil {
		return nil, e
	}
	selected, next, e := page(ctx, "DescribeUserGroups", value(in.UserGroupId), all, in.Marker, in.MaxRecords, func(v UserGroup) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &api.DescribeUserGroupsResult{Marker: next, UserGroups: api.UserGroupList{}}
	for _, v := range selected {
		g, e := s.userGroupOutput(tx, v)
		if e != nil {
			return nil, e
		}
		out.UserGroups = append(out.UserGroups, *g)
	}
	return out, nil
}
