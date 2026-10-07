package cognitoidp

import (
	"errors"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awswire"
)

func (s *Service) adminCreateUser(tx Transaction, in *api.AdminCreateUserInput) (*api.AdminCreateUserOutput, error) {
	pool, err := s.adminPool(tx, "AdminCreateUser", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	action := value(in.MessageAction)
	if action != "" && action != "SUPPRESS" && action != "RESEND" {
		return nil, failure("InvalidParameterException", "Invalid message action.")
	}
	user, err := resolveUser(tx, pool, value(in.Username))
	existing := err == nil
	if existing {
		noteUser(tx.Context(), user)
		if action != "RESEND" {
			return nil, failure("UsernameExistsException", "User account already exists")
		}
		if value(user.Data.UserStatus) != "FORCE_CHANGE_PASSWORD" {
			return nil, failure("UnsupportedUserStateException", "Only users awaiting a temporary password can receive a renewed invitation.")
		}
	} else {
		var wire *awswire.Error
		if !errors.As(err, &wire) || wire.Code != "UserNotFoundException" {
			return nil, err
		}
		if action == "RESEND" {
			return nil, err
		}
		user, err = initializeUser(pool, value(in.Username))
		if err != nil {
			return nil, err
		}
	}
	if err = setUserAttributes(pool, &user, in.UserAttributes, nil); err != nil {
		return nil, err
	}
	password := value(in.TemporaryPassword)
	if password == "" {
		// A suppressed invitation still creates a password-backed user. Generate a
		// strong unknown temporary password; the admin can replace it explicitly.
		suffix, err := controlID(64)
		if err != nil {
			return nil, err
		}
		password = "Aa1!" + suffix
	}
	if err = validatePassword(pool, password); err != nil {
		return nil, err
	}
	if action != "SUPPRESS" {
		if s.emailSender == nil || userAttribute(user, "email") == "" {
			return nil, failure("CodeDeliveryFailureException", "Email invitation delivery requires an email address and delivery provider.")
		}
		if len(in.DesiredDeliveryMediums) != 1 || string(in.DesiredDeliveryMediums[0]) != "EMAIL" {
			return nil, failure("InvalidParameterException", "Set DesiredDeliveryMediums to EMAIL; SMS delivery is not implemented.")
		}
	}
	if err = ensureUserAliases(tx, pool, &user, in.ForceAliasCreation != nil && bool(*in.ForceAliasCreation)); err != nil {
		return nil, err
	}
	user.Password, err = makePasswordVerifier(pool.Key, user.Key.Username, password)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	if !existing {
		user.Data.UserCreateDate = &now
	}
	user.Data.UserLastModifiedDate = &now
	user.Data.Enabled = ptr(api.BooleanType(true))
	user.Data.UserStatus = str[api.UserStatusType]("FORCE_CHANGE_PASSWORD")
	expires := temporaryPasswordExpiry(pool, now)
	user.PasswordExpires = &expires
	if err = tx.PutUser(user); err != nil {
		return nil, err
	}
	if action != "SUPPRESS" {
		subject, text := "Your temporary password", "Your username is "+user.Key.Username+" and temporary password is "+password+".\n"
		if t := pool.Data.AdminCreateUserConfig; t != nil && t.InviteMessageTemplate != nil {
			if t.InviteMessageTemplate.EmailSubject != nil {
				subject = string(*t.InviteMessageTemplate.EmailSubject)
			}
			if t.InviteMessageTemplate.EmailMessage != nil {
				text = strings.NewReplacer("{username}", user.Key.Username, "{####}", password).Replace(string(*t.InviteMessageTemplate.EmailMessage))
			}
		}
		if err = s.emailSender.QueueEmail(tx.Context(), EmailMessage{Pool: pool.Key, Configuration: poolEmailConfiguration(pool), To: userAttribute(user, "email"), Subject: subject, Text: text}); err != nil {
			return nil, failure("CodeDeliveryFailureException", "Unable to accept invitation email.")
		}
	}
	noteUser(tx.Context(), user)
	return &api.AdminCreateUserOutput{User: &user.Data}, nil
}
func temporaryPasswordExpiry(pool PoolRecord, now time.Time) time.Time {
	days := 7
	if pool.Data.Policies != nil && pool.Data.Policies.PasswordPolicy != nil && pool.Data.Policies.PasswordPolicy.TemporaryPasswordValidityDays != nil {
		days = int(*pool.Data.Policies.PasswordPolicy.TemporaryPasswordValidityDays)
	}
	return now.Add(time.Duration(days) * 24 * time.Hour)
}
func (s *Service) adminGetUser(tx Transaction, in *api.AdminGetUserInput) (*api.AdminGetUserOutput, error) {
	pool, err := s.adminPool(tx, "AdminGetUser", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	user, err := resolveUser(tx, pool, value(in.Username))
	if err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	d := user.Data
	return &api.AdminGetUserOutput{Username: d.Username, UserAttributes: d.Attributes, Enabled: d.Enabled, UserStatus: d.UserStatus, UserCreateDate: d.UserCreateDate, UserLastModifiedDate: d.UserLastModifiedDate, MFAOptions: d.MFAOptions}, nil
}
func (s *Service) adminDeleteUser(tx Transaction, in *api.AdminDeleteUserInput) (*api.AdminDeleteUserOutput, error) {
	pool, err := s.adminPool(tx, "AdminDeleteUser", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	user, err := resolveUser(tx, pool, value(in.Username))
	if err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	if err = tx.DeleteUser(user.Key); err != nil {
		return nil, err
	}
	return &api.AdminDeleteUserOutput{}, nil
}
func (s *Service) adminEnableUser(tx Transaction, in *api.AdminEnableUserInput) (*api.AdminEnableUserOutput, error) {
	if err := s.setUserEnabled(tx, "AdminEnableUser", value(in.UserPoolId), value(in.Username), true); err != nil {
		return nil, err
	}
	return &api.AdminEnableUserOutput{}, nil
}
func (s *Service) adminDisableUser(tx Transaction, in *api.AdminDisableUserInput) (*api.AdminDisableUserOutput, error) {
	if err := s.setUserEnabled(tx, "AdminDisableUser", value(in.UserPoolId), value(in.Username), false); err != nil {
		return nil, err
	}
	return &api.AdminDisableUserOutput{}, nil
}
func (s *Service) setUserEnabled(tx Transaction, action, poolID, username string, enabled bool) error {
	pool, err := s.adminPool(tx, action, poolID)
	if err != nil {
		return err
	}
	user, err := resolveUser(tx, pool, username)
	if err != nil {
		return err
	}
	noteUser(tx.Context(), user)
	user.Data.Enabled = ptr(api.BooleanType(enabled))
	now := s.clock.Now()
	user.Data.UserLastModifiedDate = &now
	if !enabled {
		if err = tx.RevokeUserSessions(user.Key); err != nil {
			return err
		}
	}
	return tx.PutUser(user)
}
func (s *Service) adminSetUserPassword(tx Transaction, in *api.AdminSetUserPasswordInput) (*api.AdminSetUserPasswordOutput, error) {
	pool, err := s.adminPool(tx, "AdminSetUserPassword", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	user, err := resolveUser(tx, pool, value(in.Username))
	if err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	password := value(in.Password)
	if err = validatePassword(pool, password); err != nil {
		return nil, err
	}
	user.Password, err = makePasswordVerifier(pool.Key, user.Key.Username, password)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	user.Data.UserLastModifiedDate = &now
	if in.Permanent != nil && bool(*in.Permanent) {
		user.Data.UserStatus = str[api.UserStatusType]("CONFIRMED")
		user.PasswordExpires = nil
	} else {
		user.Data.UserStatus = str[api.UserStatusType]("FORCE_CHANGE_PASSWORD")
		expires := temporaryPasswordExpiry(pool, now)
		user.PasswordExpires = &expires
	}
	if err = tx.PutUser(user); err != nil {
		return nil, err
	}
	return &api.AdminSetUserPasswordOutput{}, nil
}
func (s *Service) adminConfirmSignUp(tx Transaction, in *api.AdminConfirmSignUpInput) (*api.AdminConfirmSignUpOutput, error) {
	pool, err := s.adminPool(tx, "AdminConfirmSignUp", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	user, err := resolveUser(tx, pool, value(in.Username))
	if err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	if value(user.Data.UserStatus) != "UNCONFIRMED" {
		return nil, failure("NotAuthorizedException", "User cannot be confirmed. Current status is "+value(user.Data.UserStatus))
	}
	user.Data.UserStatus = str[api.UserStatusType]("CONFIRMED")
	now := s.clock.Now()
	user.Data.UserLastModifiedDate = &now
	if err = tx.PutUser(user); err != nil {
		return nil, err
	}
	return &api.AdminConfirmSignUpOutput{}, nil
}
func (s *Service) adminUpdateUserAttributes(tx Transaction, in *api.AdminUpdateUserAttributesInput) (*api.AdminUpdateUserAttributesOutput, error) {
	pool, err := s.adminPool(tx, "AdminUpdateUserAttributes", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	user, err := resolveUser(tx, pool, value(in.Username))
	if err != nil {
		return nil, err
	}
	previousEmail := userAttribute(user, "email")
	if err = setUserAttributes(pool, &user, in.UserAttributes, nil); err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	if err = ensureUserAliases(tx, pool, &user, false); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	user.Data.UserLastModifiedDate = &now
	if err = tx.PutUser(user); err != nil {
		return nil, err
	}
	if len(pool.Data.AutoVerifiedAttributes) > 0 && userAttribute(user, "email") != "" && userAttribute(user, "email") != previousEmail && userAttribute(user, "email_verified") != "true" {
		if _, err = s.issueEmailCode(tx, pool, user, "VERIFY_EMAIL"); err != nil {
			return nil, err
		}
	}
	return &api.AdminUpdateUserAttributesOutput{}, nil
}
func (s *Service) adminDeleteUserAttributes(tx Transaction, in *api.AdminDeleteUserAttributesInput) (*api.AdminDeleteUserAttributesOutput, error) {
	pool, err := s.adminPool(tx, "AdminDeleteUserAttributes", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	user, err := resolveUser(tx, pool, value(in.Username))
	if err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	if err = deleteUserAttributes(pool, &user, in.UserAttributeNames, nil); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	user.Data.UserLastModifiedDate = &now
	if err = tx.PutUser(user); err != nil {
		return nil, err
	}
	return &api.AdminDeleteUserAttributesOutput{}, nil
}

var usersFilterPattern = regexp.MustCompile(`^\s*([a-z_:]+)\s*(\^=|=)\s*("(?:[^"\\]|\\.)*")\s*$`)

type usersFilter struct{ name, operator, value string }

func parseUsersFilter(raw string) (usersFilter, error) {
	var f usersFilter
	if strings.TrimSpace(raw) == "" {
		return f, nil
	}
	m := usersFilterPattern.FindStringSubmatch(raw)
	if m == nil {
		return f, failure("InvalidParameterException", "Invalid filter.")
	}
	switch m[1] {
	case "username", "email", "phone_number", "name", "given_name", "family_name", "preferred_username", "cognito:user_status", "status", "sub":
	default:
		return f, failure("InvalidParameterException", "Invalid search attribute.")
	}
	val, err := strconv.Unquote(m[3])
	if err != nil {
		return f, failure("InvalidParameterException", "Invalid filter value.")
	}
	return usersFilter{name: m[1], operator: m[2], value: val}, nil
}
func (f usersFilter) matches(user UserRecord) bool {
	if f.name == "" {
		return true
	}
	v := userAttribute(user, f.name)
	switch f.name {
	case "username":
		v = user.Key.Username
	case "cognito:user_status":
		v = strings.ToLower(value(user.Data.UserStatus))
	case "status":
		v = "Disabled"
		if user.Data.Enabled != nil && bool(*user.Data.Enabled) {
			v = "Enabled"
		}
	}
	want := f.value
	if f.name == "cognito:user_status" {
		want = strings.ToLower(want)
	}
	if f.operator == "^=" {
		return strings.HasPrefix(v, want)
	}
	return v == want
}
func (s *Service) listUsers(tx Transaction, in *api.ListUsersInput) (*api.ListUsersOutput, error) {
	pool, err := s.adminPool(tx, "ListUsers", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	limit := 60
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	if limit < 1 || limit > 60 {
		return nil, failure("InvalidParameterException", "Limit must be between 1 and 60.")
	}
	filter, err := parseUsersFilter(value(in.Filter))
	if err != nil {
		return nil, err
	}
	for _, name := range in.AttributesToGet {
		if schemaAttribute(pool, string(name)) == nil {
			return nil, failure("InvalidParameterException", "Invalid requested attribute.")
		}
	}
	binding := "users:" + pool.Key.ARN() + ":" + value(in.Filter)
	for _, a := range in.AttributesToGet {
		binding += "\x00" + string(a)
	}
	cursor, err := pageCursor(value(in.PaginationToken), binding)
	if err != nil {
		return nil, err
	}
	users, err := tx.Users(pool.Key)
	if err != nil {
		return nil, err
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Key.Username < users[j].Key.Username })
	out := &api.ListUsersOutput{Users: api.UsersListType{}}
	for _, user := range users {
		if user.Key.Username <= cursor || !filter.matches(user) {
			continue
		}
		if len(out.Users) == limit {
			out.PaginationToken = str[api.SearchPaginationTokenType](nextPage(binding, value(out.Users[len(out.Users)-1].Username)))
			break
		}
		if len(in.AttributesToGet) > 0 {
			for _, name := range in.AttributesToGet {
				if userAttribute(user, string(name)) == "" {
					return nil, failure("InvalidParameterException", "A requested attribute is missing from a user.")
				}
			}
			user.Data.Attributes = slices.DeleteFunc(user.Data.Attributes, func(a api.AttributeType) bool {
				return !slices.Contains(in.AttributesToGet, api.AttributeNameType(value(a.Name)))
			})
		}
		out.Users = append(out.Users, user.Data)
	}
	return out, nil
}
