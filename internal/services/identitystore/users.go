package identitystore

import (
	"errors"
	"regexp"
	"slices"
	api "stackd/internal/awsapi/identitystore"
	"unicode/utf8"
)

func (s *Service) registerUsers() {
	register(s, "CreateUser", s.createUser)
	register(s, "DescribeUser", s.describeUser)
	register(s, "DeleteUser", s.deleteUser)
	register(s, "ListUsers", s.listUsers)
	register(s, "GetUserId", s.getUserID)
	register(s, "UpdateUser", s.updateUser)
}
func (s *Service) createUser(tx Transaction, in *api.CreateUserInput) (*api.CreateUserOutput, error) {
	store := value(in.IdentityStoreId)
	if e := s.admit(tx, "CreateUser", store, "", "", ""); e != nil {
		return nil, e
	}
	// TODO: Comeback — addresses, phones, photos, roles and enterprise extension attributes.
	if len(in.Addresses) > 0 || len(in.PhoneNumbers) > 0 || len(in.Photos) > 0 || len(in.Roles) > 0 || len(in.Extensions) > 0 {
		return nil, unsupported("Addresses, PhoneNumbers, Photos, Roles and Extensions are not implemented.")
	}
	u := User{StoreID: store, UserName: value(in.UserName), DisplayName: value(in.DisplayName), NickName: value(in.NickName), ProfileURL: value(in.ProfileUrl), Title: value(in.Title), UserType: value(in.UserType), PreferredLanguage: value(in.PreferredLanguage), Locale: value(in.Locale), Timezone: value(in.Timezone), Birthdate: value(in.Birthdate), Website: value(in.Website)}
	if in.Name != nil {
		u.Name = domainName(in.Name)
	}
	for _, v := range in.Emails {
		u.Emails = append(u.Emails, Email{Value: value(v.Value), Type: value(v.Type), Primary: v.Primary != nil && bool(*v.Primary)})
	}
	if e := validateUser(u); e != nil {
		return nil, e
	}
	if _, e := tx.UserByName(store, u.UserName); e == nil {
		return nil, conflict("UserName already exists.")
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	id, e := resourceID(store)
	if e != nil {
		return nil, e
	}
	u.ID = id
	if e := tx.PutUser(u); e != nil {
		return nil, e
	}
	return &api.CreateUserOutput{IdentityStoreId: in.IdentityStoreId, UserId: new(api.ResourceId(id))}, nil
}

var userNamePattern = regexp.MustCompile(`^[\p{L}\p{M}\p{S}\p{N}\p{P}]+$`)
var attributePattern = regexp.MustCompile(`^[\p{L}\p{M}\p{S}\p{N}\p{P}\t\n\r \x{00a0}\x{3000}]+$`)

func validOptionalText(v string) bool {
	return v == "" || (utf8.RuneCountInString(v) <= 1024 && attributePattern.MatchString(v))
}
func validateUser(u User) error {
	if u.UserName == "" || reservedName(u.UserName) || utf8.RuneCountInString(u.UserName) > 128 || !userNamePattern.MatchString(u.UserName) {
		return bad("UserName must be a non-reserved name of at most 128 characters without whitespace.")
	}
	for _, v := range []string{u.DisplayName, u.Name.Formatted, u.Name.GivenName, u.Name.FamilyName, u.Name.MiddleName, u.Name.HonorificPrefix, u.Name.HonorificSuffix, u.NickName, u.ProfileURL, u.Title, u.UserType, u.PreferredLanguage, u.Locale, u.Timezone, u.Birthdate, u.Website} {
		if !validOptionalText(v) {
			return bad("Invalid user attribute value.")
		}
	}
	if len(u.Emails) > 1 {
		return bad("At most one email is supported by Identity Store.")
	}
	for _, v := range u.Emails {
		if !validOptionalText(v.Value) || !validOptionalText(v.Type) {
			return bad("Invalid email attribute value.")
		}
	}
	return nil
}
func domainName(v *api.Name) Name {
	return Name{Formatted: value(v.Formatted), FamilyName: value(v.FamilyName), GivenName: value(v.GivenName), MiddleName: value(v.MiddleName), HonorificPrefix: value(v.HonorificPrefix), HonorificSuffix: value(v.HonorificSuffix)}
}
func apiName(v Name) *api.Name {
	if v == (Name{}) {
		return nil
	}
	return &api.Name{Formatted: text(v.Formatted), FamilyName: text(v.FamilyName), GivenName: text(v.GivenName), MiddleName: text(v.MiddleName), HonorificPrefix: text(v.HonorificPrefix), HonorificSuffix: text(v.HonorificSuffix)}
}
func apiUser(v User) api.User {
	out := api.User{IdentityStoreId: new(api.IdentityStoreId(v.StoreID)), UserId: new(api.ResourceId(v.ID)), UserName: new(api.UserName(v.UserName)), DisplayName: text(v.DisplayName), Name: apiName(v.Name), NickName: text(v.NickName), ProfileUrl: text(v.ProfileURL), Title: text(v.Title), UserType: text(v.UserType), PreferredLanguage: text(v.PreferredLanguage), Locale: text(v.Locale), Timezone: text(v.Timezone), Birthdate: text(v.Birthdate), Website: text(v.Website)}
	for _, email := range v.Emails {
		out.Emails = append(out.Emails, api.Email{Value: text(email.Value), Type: text(email.Type), Primary: new(api.BooleanType(email.Primary))})
	}
	return out
}
func (s *Service) describeUser(tx Transaction, in *api.DescribeUserInput) (*api.DescribeUserOutput, error) {
	store, id := value(in.IdentityStoreId), value(in.UserId)
	if e := s.admit(tx, "DescribeUser", store, id, "", ""); e != nil {
		return nil, e
	}
	if len(in.Extensions) > 0 {
		return nil, unsupported("Extension selection is not implemented.")
	}
	v, e := tx.User(Key{store, id})
	if e != nil {
		return nil, e
	}
	out := api.DescribeUserOutput(apiUser(v))
	return &out, nil
}
func (s *Service) deleteUser(tx Transaction, in *api.DeleteUserInput) (*api.DeleteUserOutput, error) {
	store, id := value(in.IdentityStoreId), value(in.UserId)
	if e := s.admit(tx, "DeleteUser", store, id, "", ""); e != nil {
		return nil, e
	}
	if _, e := tx.User(Key{store, id}); e != nil {
		return nil, e
	}
	return &api.DeleteUserOutput{}, tx.DeleteUser(Key{store, id})
}
func (s *Service) listUsers(tx Transaction, in *api.ListUsersInput) (*api.ListUsersOutput, error) {
	store := value(in.IdentityStoreId)
	if e := s.admit(tx, "ListUsers", store, "*", "", ""); e != nil {
		return nil, e
	}
	if len(in.Extensions) > 0 {
		return nil, unsupported("Extension selection is not implemented.")
	}
	name, e := filterName(in.Filters, "UserName")
	if e != nil {
		return nil, e
	}
	rows, e := tx.Users(store)
	if e != nil {
		return nil, e
	}
	if name != "" {
		rows = slices.DeleteFunc(rows, func(v User) bool { return v.UserName != name })
	}
	rows, next, e := page(rows, queryKey("ListUsers", store, name), in.MaxResults, in.NextToken, func(v User) string { return v.ID })
	if e != nil {
		return nil, e
	}
	out := &api.ListUsersOutput{Users: api.Users{}, NextToken: next}
	for _, v := range rows {
		out.Users = append(out.Users, apiUser(v))
	}
	return out, nil
}
func (s *Service) getUserID(tx Transaction, in *api.GetUserIdInput) (*api.GetUserIdOutput, error) {
	store := value(in.IdentityStoreId)
	if e := s.admit(tx, "GetUserId", store, "", "", ""); e != nil {
		return nil, e
	}
	name, e := uniqueName(in.AlternateIdentifier, "UserName")
	if e != nil {
		return nil, e
	}
	u, e := tx.UserByName(store, name)
	if e != nil {
		return nil, e
	}
	if e := s.admit(tx, "GetUserId", store, u.ID, "", ""); e != nil {
		return nil, e
	}
	return &api.GetUserIdOutput{IdentityStoreId: in.IdentityStoreId, UserId: new(api.ResourceId(u.ID))}, nil
}
