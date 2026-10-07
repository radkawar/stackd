package cognitoidp

import (
	"errors"

	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awswire"
)

func (s *Service) getUser(tx Transaction, input *api.GetUserInput) (*api.GetUserOutput, error) {
	_, client, user, _, err := s.accessUser(tx, value(input.AccessToken))
	if err != nil {
		return nil, err
	}
	preferred, settings := mfaPreferences(user)
	return &api.GetUserOutput{Username: str[api.UsernameType](user.Key.Username), UserAttributes: readableAttributes(user, client), PreferredMfaSetting: preferred, UserMFASettingList: settings}, nil
}

func (s *Service) updateUserAttributes(tx Transaction, input *api.UpdateUserAttributesInput) (*api.UpdateUserAttributesOutput, error) {
	pool, client, user, _, err := s.accessUser(tx, value(input.AccessToken))
	if err != nil {
		return nil, err
	}
	previousEmail := userAttribute(user, "email")
	if err := setUserAttributes(pool, &user, input.UserAttributes, &client); err != nil {
		return nil, err
	}
	if err := ensureUserAliases(tx, pool, &user, false); err != nil {
		return nil, err
	}
	user.Data.UserLastModifiedDate = ptr(s.clock.Now().UTC())
	if err := tx.PutUser(user); err != nil {
		return nil, err
	}
	out := &api.UpdateUserAttributesOutput{}
	if len(pool.Data.AutoVerifiedAttributes) > 0 && userAttribute(user, "email") != "" && userAttribute(user, "email") != previousEmail {
		details, err := s.issueEmailCode(tx, pool, user, "VERIFY_EMAIL")
		if err != nil {
			return nil, err
		}
		out.CodeDeliveryDetailsList = api.CodeDeliveryDetailsListType{*details}
	}
	return out, nil
}

func (s *Service) deleteUserAttributes(tx Transaction, input *api.DeleteUserAttributesInput) (*api.DeleteUserAttributesOutput, error) {
	pool, client, user, _, err := s.accessUser(tx, value(input.AccessToken))
	if err != nil {
		return nil, err
	}
	if err := deleteUserAttributes(pool, &user, input.UserAttributeNames, &client); err != nil {
		return nil, err
	}
	user.Data.UserLastModifiedDate = ptr(s.clock.Now().UTC())
	if err := tx.PutUser(user); err != nil {
		return nil, err
	}
	return &api.DeleteUserAttributesOutput{}, nil
}

func (s *Service) deleteUser(tx Transaction, input *api.DeleteUserInput) (*api.DeleteUserOutput, error) {
	_, _, user, _, err := s.accessUser(tx, value(input.AccessToken))
	if err != nil {
		return nil, err
	}
	if err := tx.DeleteUser(user.Key); err != nil {
		return nil, err
	}
	return &api.DeleteUserOutput{}, nil
}

func (s *Service) changePassword(tx Transaction, input *api.ChangePasswordInput) (*api.ChangePasswordOutput, error) {
	pool, _, user, _, err := s.accessUser(tx, value(input.AccessToken))
	if err != nil {
		return nil, err
	}
	matches, err := matchesPassword(pool.Key, user.Key.Username, value(input.PreviousPassword), user.Password)
	if err != nil {
		return nil, err
	}
	if !matches {
		return nil, failure("NotAuthorizedException", "Incorrect username or password.")
	}
	password := value(input.ProposedPassword)
	if err := validatePassword(pool, password); err != nil {
		return nil, err
	}
	user.Password, err = makePasswordVerifier(pool.Key, user.Key.Username, password)
	if err != nil {
		return nil, err
	}
	user.PasswordExpires = nil
	user.Data.UserLastModifiedDate = ptr(s.clock.Now().UTC())
	if err := tx.PutUser(user); err != nil {
		return nil, err
	}
	return &api.ChangePasswordOutput{}, nil
}

func (s *Service) signUp(tx Transaction, input *api.SignUpInput) (*api.SignUpOutput, error) {
	pool, client, err := s.authClient(tx, "SignUp", "", value(input.ClientId))
	if err != nil {
		return nil, err
	}
	username := value(input.Username)
	if err := checkSecretHash(client, username, value(input.SecretHash)); err != nil {
		return nil, err
	}
	if config := pool.Data.AdminCreateUserConfig; config != nil && config.AllowAdminCreateUserOnly != nil && bool(*config.AllowAdminCreateUserOnly) {
		return nil, failure("NotAuthorizedException", "SignUp is not permitted for this user pool")
	}
	existing, err := resolveUser(tx, pool, username)
	if err == nil {
		noteUser(tx.Context(), existing)
		return nil, failure("UsernameExistsException", "User already exists")
	}
	var apiErr *awswire.Error
	if !errors.Is(err, ErrNotFound) && !(errors.As(err, &apiErr) && apiErr.Code == "UserNotFoundException") {
		return nil, err
	}
	user, err := s.initializeSignUpUser(tx, pool, username)
	if err != nil {
		return nil, err
	}
	if err := setUserAttributes(pool, &user, input.UserAttributes, &client); err != nil {
		return nil, err
	}
	for _, name := range []string{"email", "phone_number"} {
		if userAttribute(user, name) != "" {
			putUserAttribute(&user, name+"_verified", "false")
		}
	}
	for _, attribute := range pool.Data.SchemaAttributes {
		if attribute.Required != nil && bool(*attribute.Required) && userAttribute(user, value(attribute.Name)) == "" {
			return nil, failure("InvalidParameterException", "Missing required attribute "+value(attribute.Name))
		}
	}
	if err := ensureUserAliases(tx, pool, &user, false); err != nil {
		return nil, err
	}
	password := value(input.Password)
	if password == "" {
		return nil, failure("InvalidParameterException", "Password is required")
	}
	if err := validatePassword(pool, password); err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	user.Data.Enabled = ptr(api.BooleanType(true))
	user.Data.UserStatus = str[api.UserStatusType]("UNCONFIRMED")
	user.Data.UserCreateDate = ptr(now)
	user.Data.UserLastModifiedDate = ptr(now)
	if err := s.preSignUp(tx, pool, client, &user, false); err != nil {
		return nil, err
	}
	if err := ensureUserAliases(tx, pool, &user, true); err != nil {
		return nil, err
	}
	user.Password, err = makePasswordVerifier(pool.Key, user.Key.Username, password)
	if err != nil {
		return nil, err
	}
	if err := tx.PutUser(user); err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	confirmed := value(user.Data.UserStatus) == "CONFIRMED"
	out := &api.SignUpOutput{UserConfirmed: new(api.BooleanType(confirmed)), UserSub: new(api.StringType(userAttribute(user, "sub")))}
	if confirmed {
		s.postConfirmation(tx, pool, client.Key.ID, user, "PostConfirmation_ConfirmSignUp", input.ClientMetadata)
	}
	if !confirmed && len(pool.Data.AutoVerifiedAttributes) > 0 {
		out.CodeDeliveryDetails, err = s.issueEmailCode(tx, pool, user, "SIGN_UP")
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
