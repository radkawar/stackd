package memorydb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	engine "stackd/engine/valkey"
	api "stackd/internal/awsapi/memorydb"
	"strings"
)

func defaultUser(sc Scope) User {
	return User{Key: Key{Scope: sc, Kind: "user", Name: "default"}, AccessString: "on ~* &* +@all", Authentication: "no-password", Status: "active"}
}
func defaultACL(sc Scope) ACL {
	return ACL{Key: Key{Scope: sc, Kind: "acl", Name: "open-access"}, Users: []string{"default"}, Status: "active"}
}
func (s *Service) loadUser(ctx context.Context, r Reader, action, name string) (User, error) {
	k, e := keyFor(ctx, "user", name)
	if e != nil {
		return User{}, e
	}
	var v User
	if k.Name == "default" {
		v = defaultUser(k.Scope)
	} else {
		v, e = r.User(k)
		if errors.Is(e, ErrNotFound) {
			e = notFound("user")
		}
		if e != nil {
			return v, e
		}
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}
func (s *Service) loadACL(ctx context.Context, r Reader, action, name string) (ACL, error) {
	k, e := keyFor(ctx, "acl", name)
	if e != nil {
		return ACL{}, e
	}
	var v ACL
	if k.Name == "open-access" {
		v = defaultACL(k.Scope)
	} else {
		v, e = r.ACL(k)
		if errors.Is(e, ErrNotFound) {
			e = notFound("acl")
		}
		if e != nil {
			return v, e
		}
	}
	if action == "CreateCluster" || action == "UpdateCluster" {
		return v, nil
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}
func authentication(in *api.AuthenticationMode) (string, []string, error) {
	if in == nil {
		return "", nil, invalid("AuthenticationMode is required.")
	}
	kind := value(in.Type)
	if kind == "iam" {
		return "", nil, unsupported("IAM engine authentication is not implemented.")
	}
	if kind != "password" {
		return "", nil, invalid("Authentication type must be password or iam.")
	}
	if len(in.Passwords) < 1 || len(in.Passwords) > 2 {
		return "", nil, invalid("One or two passwords are required.")
	}
	hashes := make([]string, 0, len(in.Passwords))
	for _, p := range in.Passwords {
		password := string(p)
		if len(password) < 16 || len(password) > 128 {
			return "", nil, invalid("Passwords must have 16 to 128 printable characters.")
		}
		for _, c := range password {
			if c < 32 || c > 126 || strings.ContainsRune(",\"/@", c) {
				return "", nil, invalid("Password contains a prohibited character.")
			}
		}
		sum := sha256.Sum256([]byte(password))
		hashes = append(hashes, hex.EncodeToString(sum[:]))
	}
	slices.Sort(hashes)
	return kind, slices.Compact(hashes), nil
}
func nativeUser(v User) engine.User {
	return engine.User{Name: v.Key.Name, AccessString: v.AccessString, PasswordHashes: v.PasswordHashes, NoPassword: v.Authentication == "no-password"}
}
func (s *Service) validateUser(v User) error {
	if e := s.ensureRuntime(); e != nil {
		return e
	}
	if v.Key.Name == "stackd-controller" {
		return invalid("Reserved username.")
	}
	if strings.TrimSpace(v.AccessString) == "" {
		return invalid("AccessString must not be empty.")
	}
	if e := engine.ValidateUsers([]engine.User{nativeUser(v)}); e != nil {
		return invalid(e.Error())
	}
	return nil
}
func userDTO(v User, acls []ACL) *api.User {
	out := &api.User{Name: new(api.String(v.Key.Name)), ARN: new(api.String(v.Key.ARN())), Status: new(api.String(v.Status)), AccessString: new(api.String(v.AccessString)), Authentication: &api.Authentication{Type: new(api.AuthenticationType(v.Authentication)), PasswordCount: new(api.IntegerOptional(len(v.PasswordHashes)))}}
	for _, a := range acls {
		if slices.Contains(a.Users, v.Key.Name) {
			out.ACLNames = append(out.ACLNames, api.ACLName(a.Key.Name))
		}
	}
	return out
}
func aclDTO(v ACL, clusters []Cluster) *api.ACL {
	out := &api.ACL{Name: new(api.String(v.Key.Name)), ARN: new(api.String(v.Key.ARN())), Status: new(api.String(v.Status))}
	for _, name := range v.Users {
		out.UserNames = append(out.UserNames, api.UserName(name))
	}
	for _, c := range clusters {
		if c.ACLName == v.Key.Name {
			out.Clusters = append(out.Clusters, api.String(c.Key.Name))
		}
	}
	return out
}
func (s *Service) createUser(ctx context.Context, tx Transaction, in *api.CreateUserRequest) (*api.CreateUserResponse, error) {
	k, e := keyFor(ctx, "user", value(in.UserName))
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
	if k.Name == "default" {
		return nil, exists("user")
	}
	if _, e = tx.User(k); e == nil {
		return nil, exists("user")
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	auth, hashes, e := authentication(in.AuthenticationMode)
	if e != nil {
		return nil, e
	}
	v := User{Key: k, AccessString: value(in.AccessString), Authentication: auth, PasswordHashes: hashes, Status: "active", Tags: tags}
	if e = s.validateUser(v); e != nil {
		return nil, e
	}
	if e = tx.PutUser(v); e != nil {
		return nil, e
	}
	return &api.CreateUserResponse{User: userDTO(v, nil)}, nil
}
func (s *Service) updateUser(ctx context.Context, tx Transaction, in *api.UpdateUserRequest) (*api.UpdateUserResponse, error) {
	v, e := s.loadUser(ctx, tx, "UpdateUser", value(in.UserName))
	if e != nil {
		return nil, e
	}
	if v.Key.Name == "default" || v.Status != "active" {
		return nil, stateError("user")
	}
	if in.AuthenticationMode != nil {
		v.Authentication, v.PasswordHashes, e = authentication(in.AuthenticationMode)
		if e != nil {
			return nil, e
		}
	}
	if in.AccessString != nil {
		v.AccessString = value(in.AccessString)
	}
	if e = s.validateUser(v); e != nil {
		return nil, e
	}
	acls, e := tx.ACLs(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	attached := false
	for _, a := range acls {
		if slices.Contains(a.Users, v.Key.Name) {
			changed, e := s.scheduleACLClusters(tx, a)
			if e != nil {
				return nil, e
			}
			attached = attached || changed
			if changed {
				a.Status = "modifying"
				if e = tx.PutACL(a); e != nil {
					return nil, e
				}
			}
		}
	}
	if attached {
		v.Status = "modifying"
	}
	if e = tx.PutUser(v); e != nil {
		return nil, e
	}
	return &api.UpdateUserResponse{User: userDTO(v, acls)}, nil
}
func (s *Service) deleteUser(ctx context.Context, tx Transaction, in *api.DeleteUserRequest) (*api.DeleteUserResponse, error) {
	v, e := s.loadUser(ctx, tx, "DeleteUser", value(in.UserName))
	if e != nil {
		return nil, e
	}
	if v.Key.Name == "default" || v.Status != "active" {
		return nil, stateError("user")
	}
	acls, e := tx.ACLs(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	attached := false
	for _, a := range acls {
		if slices.Contains(a.Users, v.Key.Name) {
			a.Users = slices.DeleteFunc(a.Users, func(n string) bool { return n == v.Key.Name })
			changed, e := s.scheduleACLClusters(tx, a)
			if e != nil {
				return nil, e
			}
			attached = attached || changed
			if changed {
				a.Status = "modifying"
			}
			if e = tx.PutACL(a); e != nil {
				return nil, e
			}
		}
	}
	v.Status = "deleting"
	if attached {
		e = tx.PutUser(v)
	} else {
		e = tx.DeleteUser(v.Key)
	}
	if e != nil {
		return nil, e
	}
	return &api.DeleteUserResponse{User: userDTO(v, nil)}, nil
}
func (s *Service) scheduleACLClusters(tx Transaction, a ACL) (bool, error) {
	all, e := tx.Clusters(a.Key.Scope)
	if e != nil {
		return false, e
	}
	changed := false
	for _, v := range all {
		if v.ACLName != a.Key.Name {
			continue
		}
		if v.Status == "deleting" {
			return false, stateError("cluster")
		}
		s.scheduleCluster(&v, "access")
		if e = tx.PutCluster(v); e != nil {
			return false, e
		}
		changed = true
	}
	return changed, nil
}
func validateACLUsers(r Reader, sc Scope, names []string) error {
	seen := map[string]bool{}
	for _, name := range names {
		if name == "default" {
			return invalid("The default user belongs only to open-access.")
		}
		if seen[name] {
			return invalid("Duplicate user name.")
		}
		seen[name] = true
		v, e := r.User(Key{Scope: sc, Kind: "user", Name: name})
		if errors.Is(e, ErrNotFound) {
			return notFound("user")
		}
		if e != nil {
			return e
		}
		if v.Status != "active" {
			return stateError("user")
		}
	}
	return nil
}
func (s *Service) createACL(ctx context.Context, tx Transaction, in *api.CreateACLRequest) (*api.CreateACLResponse, error) {
	k, e := keyFor(ctx, "acl", value(in.ACLName))
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateACL", k, nil, tags); e != nil {
		return nil, e
	}
	if k.Name == "open-access" {
		return nil, exists("acl")
	}
	if _, e = tx.ACL(k); e == nil {
		return nil, exists("acl")
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	v := ACL{Key: k, Status: "active", Tags: tags}
	for _, n := range in.UserNames {
		v.Users = append(v.Users, strings.ToLower(string(n)))
	}
	if e = validateACLUsers(tx, k.Scope, v.Users); e != nil {
		return nil, e
	}
	slices.Sort(v.Users)
	if e = tx.PutACL(v); e != nil {
		return nil, e
	}
	return &api.CreateACLResponse{ACL: aclDTO(v, nil)}, nil
}
func (s *Service) updateACL(ctx context.Context, tx Transaction, in *api.UpdateACLRequest) (*api.UpdateACLResponse, error) {
	v, e := s.loadACL(ctx, tx, "UpdateACL", value(in.ACLName))
	if e != nil {
		return nil, e
	}
	if v.Key.Name == "open-access" || v.Status != "active" {
		return nil, stateError("acl")
	}
	for _, raw := range in.UserNamesToRemove {
		n := strings.ToLower(string(raw))
		if !slices.Contains(v.Users, n) {
			return nil, invalid("User is not a member of the ACL.")
		}
		v.Users = slices.DeleteFunc(v.Users, func(x string) bool { return x == n })
	}
	for _, raw := range in.UserNamesToAdd {
		n := strings.ToLower(string(raw))
		if slices.Contains(v.Users, n) {
			return nil, invalid("User is already a member of the ACL.")
		}
		v.Users = append(v.Users, n)
	}
	if e = validateACLUsers(tx, v.Key.Scope, v.Users); e != nil {
		return nil, e
	}
	slices.Sort(v.Users)
	attached, e := s.scheduleACLClusters(tx, v)
	if e != nil {
		return nil, e
	}
	if attached {
		v.Status = "modifying"
	}
	if e = tx.PutACL(v); e != nil {
		return nil, e
	}
	clusters, e := tx.Clusters(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	return &api.UpdateACLResponse{ACL: aclDTO(v, clusters)}, nil
}
func (s *Service) deleteACL(ctx context.Context, tx Transaction, in *api.DeleteACLRequest) (*api.DeleteACLResponse, error) {
	v, e := s.loadACL(ctx, tx, "DeleteACL", value(in.ACLName))
	if e != nil {
		return nil, e
	}
	if v.Key.Name == "open-access" || v.Status != "active" {
		return nil, stateError("acl")
	}
	clusters, e := tx.Clusters(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	for _, c := range clusters {
		if c.ACLName == v.Key.Name {
			return nil, stateError("acl")
		}
	}
	v.Status = "deleting"
	if e = tx.DeleteACL(v.Key); e != nil {
		return nil, e
	}
	return &api.DeleteACLResponse{ACL: aclDTO(v, nil)}, nil
}
func (s *Service) describeUsers(ctx context.Context, tx Transaction, in *api.DescribeUsersRequest) (*api.DescribeUsersResponse, error) {
	maxResults := in.MaxResults
	if maxResults == nil {
		maxResults = new(api.IntegerOptional(50))
	}
	if *maxResults < 1 || *maxResults > 50 {
		return nil, invalid("MaxResults must be between 1 and 50.")
	}
	for _, filter := range in.Filters {
		if value(filter.Name) != "user-name" || len(filter.Values) == 0 {
			return nil, invalid("Invalid filter name or empty values.")
		}
	}
	var rows []User
	if in.UserName != nil {
		v, e := s.loadUser(ctx, tx, "DescribeUsers", value(in.UserName))
		if e != nil {
			return nil, e
		}
		rows = []User{v}
	} else {
		if e := s.authorize(ctx, "DescribeUsers", Key{}, nil, nil); e != nil {
			return nil, e
		}
		var e error
		rows, e = tx.Users(scopeFor(ctx))
		if e != nil {
			return nil, e
		}
		rows = append(rows, defaultUser(scopeFor(ctx)))
		slices.SortFunc(rows, func(a, b User) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	}
	for _, filter := range in.Filters {
		filtered := rows[:0]
		for _, row := range rows {
			for _, wanted := range filter.Values {
				if row.Key.Name == string(wanted) {
					filtered = append(filtered, row)
					break
				}
			}
		}
		rows = filtered
	}
	filterDocument, e := json.Marshal(in.Filters)
	if e != nil {
		return nil, e
	}
	rows, next, e := page(rows, maxResults, in.NextToken, binding(ctx, "DescribeUsers", value(in.UserName)+":"+string(filterDocument)), func(v User) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	acls, e := tx.ACLs(scopeFor(ctx))
	if e != nil {
		return nil, e
	}
	acls = append(acls, defaultACL(scopeFor(ctx)))
	out := &api.DescribeUsersResponse{NextToken: next, Users: make(api.UserList, 0, len(rows))}
	for _, v := range rows {
		out.Users = append(out.Users, *userDTO(v, acls))
	}
	return out, nil
}
func (s *Service) describeACLs(ctx context.Context, tx Transaction, in *api.DescribeACLsRequest) (*api.DescribeACLsResponse, error) {
	var rows []ACL
	if in.ACLName != nil {
		v, e := s.loadACL(ctx, tx, "DescribeACLs", value(in.ACLName))
		if e != nil {
			return nil, e
		}
		rows = []ACL{v}
	} else {
		if e := s.authorize(ctx, "DescribeACLs", Key{}, nil, nil); e != nil {
			return nil, e
		}
		var e error
		rows, e = tx.ACLs(scopeFor(ctx))
		if e != nil {
			return nil, e
		}
		rows = append(rows, defaultACL(scopeFor(ctx)))
		slices.SortFunc(rows, func(a, b ACL) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	}
	rows, next, e := page(rows, in.MaxResults, in.NextToken, binding(ctx, "DescribeACLs", value(in.ACLName)), func(v ACL) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	clusters, e := tx.Clusters(scopeFor(ctx))
	if e != nil {
		return nil, e
	}
	out := &api.DescribeACLsResponse{NextToken: next}
	for _, v := range rows {
		out.ACLs = append(out.ACLs, *aclDTO(v, clusters))
	}
	return out, nil
}
