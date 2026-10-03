package mq

import (
	"cmp"
	"context"
	"regexp"
	"slices"
	api "stackd/internal/awsapi/mq"
	"strings"
)

var userName = regexp.MustCompile(`^[A-Za-z0-9_.~-]{2,100}$`)

func registerUsers(s *Service) {
	register(s, "CreateUser", s.createUser)
	register(s, "UpdateUser", s.updateUser)
	register(s, "DeleteUser", s.deleteUser)
	register(s, "DescribeUser", s.describeUser)
	register(s, "ListUsers", s.listUsers)
}
func validateUser(username, password string, groups []string, replication bool) error {
	if !userName.MatchString(username) {
		return invalid("Invalid broker username")
	}
	if len(password) < 12 || len(password) > 250 || strings.ContainsAny(password, ",:=\x00\r\n") {
		return invalid("Password must contain 12-250 characters without commas, colons or equal signs")
	}
	if strings.Contains(password, "${") || strings.Contains(password, "#{") {
		return invalid("Native broker passwords cannot contain Spring expression delimiters")
	}
	unique := map[rune]bool{}
	for _, r := range password {
		unique[r] = true
	}
	if len(unique) < 4 {
		return invalid("Password must contain at least four unique characters")
	}
	if len(groups) > 20 {
		return invalid("A user may have at most 20 groups")
	}
	for _, g := range groups {
		if !userName.MatchString(g) {
			return invalid("Invalid user group")
		}
	}
	// TODO: Comeback expose the real CRDR replication identity before admitting this privilege.
	if replication {
		return invalid("Replication users require an unavailable native owner")
	}
	return nil
}
func listStrings[S ~[]E, E ~string](in S) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
func truth[T ~bool](p *T) bool { return p != nil && bool(*p) }
func brokerUsers(v BrokerRecord) []UserRecord {
	if v.Users != nil {
		return v.Users
	}
	if v.Username != "" {
		return []UserRecord{{Username: v.Username, Password: v.Password}}
	}
	return nil
}
func (s *Service) userBroker(ctx context.Context, t Transaction, id, action string, mutable bool) (BrokerRecord, error) {
	v, e := s.load(ctx, t, id, action)
	if e != nil {
		return v, e
	}
	if v.Engine != "ACTIVEMQ" {
		return v, invalid("Amazon MQ user operations do not apply to RabbitMQ; use its native management API")
	}
	if mutable && v.State != "RUNNING" {
		return v, failure("ConflictException", "Broker must be running before changing users", 409)
	}
	v.Users = brokerUsers(v)
	return v, nil
}
func findUser(users []UserRecord, name string) int {
	return slices.IndexFunc(users, func(u UserRecord) bool { return u.Username == name })
}
func (s *Service) createUser(ctx context.Context, t Transaction, in *api.CreateUserInput) (*api.CreateUserOutput, error) {
	v, e := s.userBroker(ctx, t, value(in.BrokerId), "CreateUser", true)
	if e != nil {
		return nil, e
	}
	username, password := value(in.Username), value(in.Password)
	groups := listStrings(in.Groups)
	if e = validateUser(username, password, groups, truth(in.ReplicationUser)); e != nil {
		return nil, e
	}
	if findUser(v.Users, username) >= 0 {
		return nil, failure("ConflictException", "User already exists", 409)
	}
	v.Users = append(v.Users, UserRecord{Username: username, PendingChange: "CREATE", PendingPassword: password, PendingGroups: groups, PendingConsoleAccess: truth(in.ConsoleAccess)})
	slices.SortFunc(v.Users, func(a, b UserRecord) int { return cmp.Compare(a.Username, b.Username) })
	s.scheduleMaintenance(&v)
	return &api.CreateUserOutput{}, t.PutBroker(v)
}
func (s *Service) updateUser(ctx context.Context, t Transaction, in *api.UpdateUserInput) (*api.UpdateUserOutput, error) {
	v, e := s.userBroker(ctx, t, value(in.BrokerId), "UpdateUser", true)
	if e != nil {
		return nil, e
	}
	i := findUser(v.Users, value(in.Username))
	if i < 0 {
		return nil, ErrNotFound
	}
	u := &v.Users[i]
	if u.PendingChange == "DELETE" {
		return nil, failure("ConflictException", "User is pending deletion", 409)
	}
	password, groups, console := u.Password, u.Groups, u.ConsoleAccess
	if u.PendingChange != "" {
		password, groups, console = u.PendingPassword, u.PendingGroups, u.PendingConsoleAccess
	}
	if in.Password != nil {
		password = value(in.Password)
	}
	if in.Groups != nil {
		groups = listStrings(in.Groups)
	}
	if in.ConsoleAccess != nil {
		console = truth(in.ConsoleAccess)
	}
	// Legacy effective credentials live only in the native authentication file.
	// Groups or console changes must not replace that password with an empty credential.
	if password == "" && in.Password == nil {
		if !userName.MatchString(u.Username) || len(groups) > 20 {
			return nil, invalid("Invalid user")
		}
		for _, g := range groups {
			if !userName.MatchString(g) {
				return nil, invalid("Invalid user group")
			}
		}
		if truth(in.ReplicationUser) {
			return nil, invalid("Replication users require an unavailable native owner")
		}
	} else if e = validateUser(u.Username, password, groups, truth(in.ReplicationUser)); e != nil {
		return nil, e
	}
	if u.PendingChange != "CREATE" {
		u.PendingChange = "UPDATE"
	}
	u.PendingPassword = password
	u.PendingGroups = slices.Clone(groups)
	u.PendingConsoleAccess = console
	s.scheduleMaintenance(&v)
	return &api.UpdateUserOutput{}, t.PutBroker(v)
}
func (s *Service) deleteUser(ctx context.Context, t Transaction, in *api.DeleteUserInput) (*api.DeleteUserOutput, error) {
	v, e := s.userBroker(ctx, t, value(in.BrokerId), "DeleteUser", true)
	if e != nil {
		return nil, e
	}
	i := findUser(v.Users, value(in.Username))
	if i < 0 {
		return nil, ErrNotFound
	}
	if v.Users[i].PendingChange == "CREATE" {
		v.Users = slices.Delete(v.Users, i, i+1)
	} else {
		v.Users[i].PendingChange = "DELETE"
		v.Users[i].PendingPassword = ""
		v.Users[i].PendingGroups = nil
	}
	s.scheduleMaintenance(&v)
	return &api.DeleteUserOutput{}, t.PutBroker(v)
}
func (s *Service) describeUser(ctx context.Context, t Transaction, in *api.DescribeUserInput) (*api.DescribeUserOutput, error) {
	v, e := s.userBroker(ctx, t, value(in.BrokerId), "DescribeUser", false)
	if e != nil {
		return nil, e
	}
	i := findUser(v.Users, value(in.Username))
	if i < 0 {
		return nil, ErrNotFound
	}
	u := v.Users[i]
	o := &api.DescribeUserOutput{}
	text(&o.BrokerId, v.ID)
	text(&o.Username, u.Username)
	if u.PendingChange != "CREATE" {
		boolean(&o.ConsoleAccess, u.ConsoleAccess)
		stringList(&o.Groups, u.Groups)
	}
	if u.PendingChange != "" {
		o.Pending = &api.UserPendingChanges{}
		text(&o.Pending.PendingChange, u.PendingChange)
		if u.PendingChange != "DELETE" {
			boolean(&o.Pending.ConsoleAccess, u.PendingConsoleAccess)
			stringList(&o.Pending.Groups, u.PendingGroups)
		}
	}
	return o, nil
}
func (s *Service) listUsers(ctx context.Context, t Transaction, in *api.ListUsersInput) (*api.ListUsersOutput, error) {
	v, e := s.userBroker(ctx, t, value(in.BrokerId), "ListUsers", false)
	if e != nil {
		return nil, e
	}
	kind := "users:" + v.ID
	limit, after, e := page(ctx, kind, in.MaxResults, value(in.NextToken))
	if e != nil {
		return nil, e
	}
	o := &api.ListUsersOutput{}
	text(&o.BrokerId, v.ID)
	number(&o.MaxResults, limit)
	last := ""
	slices.SortFunc(v.Users, func(a, b UserRecord) int { return cmp.Compare(a.Username, b.Username) })
	for _, u := range v.Users {
		if u.Username <= after {
			continue
		}
		if len(o.Users) == limit {
			text(&o.NextToken, pageToken(ctx, kind, last))
			break
		}
		o.Users = append(o.Users, userSummary(u))
		last = u.Username
	}
	return o, nil
}
func userSummary(u UserRecord) api.UserSummary {
	o := api.UserSummary{}
	text(&o.Username, u.Username)
	if u.PendingChange != "" {
		text(&o.PendingChange, u.PendingChange)
	}
	return o
}
func applyPending(v BrokerRecord) BrokerRecord {
	v.Users = slices.Clone(brokerUsers(v))
	users := v.Users[:0]
	for _, u := range v.Users {
		switch u.PendingChange {
		case "DELETE":
			continue
		case "CREATE", "UPDATE":
			u.Password = u.PendingPassword
			u.Groups = slices.Clone(u.PendingGroups)
			u.ConsoleAccess = u.PendingConsoleAccess
		}
		u.PendingChange = ""
		u.PendingPassword = ""
		u.PendingGroups = nil
		u.PendingConsoleAccess = false
		users = append(users, u)
	}
	v.Users = users
	if v.PendingConfiguration.ID != "" {
		if v.Configuration.ID != "" {
			v.ConfigurationHistory = append(slices.Clone(v.ConfigurationHistory), v.Configuration)
		}
		v.Configuration = v.PendingConfiguration
		v.PendingConfiguration = ConfigurationReference{}
	}
	if v.PendingLogs != nil {
		v.Logs = *v.PendingLogs
		v.PendingLogs = nil
	}
	return v
}
