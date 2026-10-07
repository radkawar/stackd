package cognitoidp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awswire"
)

func registerAuthentication(s *Service) {
	register(s, "InitiateAuth", s.initiateAuth)
	register(s, "AdminInitiateAuth", s.adminInitiateAuth)
	register(s, "RespondToAuthChallenge", s.respondToAuthChallenge)
	register(s, "AdminRespondToAuthChallenge", s.adminRespondToAuthChallenge)
	register(s, "GetTokensFromRefreshToken", s.getTokensFromRefreshToken)
	register(s, "RevokeToken", s.revokeToken)
	register(s, "GlobalSignOut", s.globalSignOut)
	register(s, "AdminUserGlobalSignOut", s.adminUserGlobalSignOut)
	register(s, "GetUser", s.getUser)
	register(s, "ChangePassword", s.changePassword)
	register(s, "SignUp", s.signUp)
	register(s, "UpdateUserAttributes", s.updateUserAttributes)
	register(s, "DeleteUserAttributes", s.deleteUserAttributes)
	register(s, "DeleteUser", s.deleteUser)
}

func (s *Service) authClient(tx Transaction, action, poolID, clientID string) (PoolRecord, ClientRecord, error) {
	var pool PoolRecord
	var client ClientRecord
	var err error
	if strings.HasPrefix(action, "Admin") {
		pool, err = s.adminPool(tx, action, poolID)
		if err != nil {
			return PoolRecord{}, ClientRecord{}, err
		}
		client, err = tx.Client(ClientKey{PoolKey: pool.Key, ID: clientID})
		if errors.Is(err, ErrNotFound) {
			return PoolRecord{}, ClientRecord{}, failure("ResourceNotFoundException", "User pool client "+clientID+" does not exist in user pool "+poolID+".")
		}
	} else {
		client, err = publicClient(tx, clientID)
		if errors.Is(err, ErrNotFound) {
			return PoolRecord{}, ClientRecord{}, failure("ResourceNotFoundException", "User pool client "+clientID+" does not exist.")
		}
		if err == nil {
			pool, err = tx.Pool(client.Key.PoolKey)
		}
	}
	if err != nil {
		return PoolRecord{}, ClientRecord{}, err
	}
	notePool(tx.Context(), pool.Key)
	return pool, client, nil
}

func (s *Service) initiateAuth(tx Transaction, input *api.InitiateAuthInput) (*api.InitiateAuthOutput, error) {
	pool, client, err := s.authClient(tx, "InitiateAuth", "", value(input.ClientId))
	if err != nil {
		return nil, err
	}
	return s.beginAuth(tx, pool, client, value(input.AuthFlow), input.AuthParameters, false)
}

func (s *Service) adminInitiateAuth(tx Transaction, input *api.AdminInitiateAuthInput) (*api.AdminInitiateAuthOutput, error) {
	pool, client, err := s.authClient(tx, "AdminInitiateAuth", value(input.UserPoolId), value(input.ClientId))
	if err != nil {
		return nil, err
	}
	out, err := s.beginAuth(tx, pool, client, value(input.AuthFlow), input.AuthParameters, true)
	if err != nil {
		return nil, err
	}
	return &api.AdminInitiateAuthOutput{AuthenticationResult: out.AuthenticationResult, ChallengeName: out.ChallengeName, ChallengeParameters: out.ChallengeParameters, Session: out.Session}, nil
}

func authFlowEnabled(client ClientRecord, flow string) bool {
	if flow == "ADMIN_NO_SRP_AUTH" {
		flow = "ADMIN_USER_PASSWORD_AUTH"
	}
	if flow == "REFRESH_TOKEN" {
		flow = "REFRESH_TOKEN_AUTH"
	}
	flows := client.Data.ExplicitAuthFlows
	if len(flows) == 0 {
		return flow == "USER_SRP_AUTH" || flow == "REFRESH_TOKEN_AUTH" || flow == "CUSTOM_AUTH"
	}
	if slices.Contains(flows, api.ExplicitAuthFlowsType("ALLOW_"+flow)) {
		return true
	}
	if flow == "ADMIN_USER_PASSWORD_AUTH" && slices.Contains(flows, api.ExplicitAuthFlowsType("ADMIN_NO_SRP_AUTH")) {
		return true
	}
	if flow == "USER_PASSWORD_AUTH" && slices.Contains(flows, api.ExplicitAuthFlowsType("USER_PASSWORD_AUTH")) {
		return true
	}
	if flow == "REFRESH_TOKEN_AUTH" {
		// Legacy (pre-ALLOW_*) flow settings retained refresh authentication.
		for _, setting := range flows {
			if strings.HasPrefix(string(setting), "ALLOW_") {
				return false
			}
		}
		return true
	}
	return false
}

func checkSecretHash(client ClientRecord, username, supplied string) error {
	secret := value(client.Data.ClientSecret)
	if secret == "" {
		return nil
	}
	if supplied == "" {
		return failure("NotAuthorizedException", "Client "+client.Key.ID+" is configured with secret but SECRET_HASH was not received")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(username + client.Key.ID))
	decoded, err := base64.StdEncoding.DecodeString(supplied)
	if err != nil || !hmac.Equal(decoded, mac.Sum(nil)) {
		return failure("NotAuthorizedException", "Unable to verify secret hash for client "+client.Key.ID)
	}
	return nil
}

func userEnabled(user UserRecord) error {
	if user.Data.Enabled == nil || !bool(*user.Data.Enabled) {
		return failure("NotAuthorizedException", "User is disabled.")
	}
	return nil
}

func (s *Service) authUserStatus(user UserRecord) error {
	if err := userEnabled(user); err != nil {
		return err
	}
	switch value(user.Data.UserStatus) {
	case "CONFIRMED":
		return nil
	case "FORCE_CHANGE_PASSWORD":
		if user.PasswordExpires != nil && !s.clock.Now().Before(*user.PasswordExpires) {
			return failure("NotAuthorizedException", "Temporary password has expired and must be reset by an administrator.")
		}
		return nil
	case "UNCONFIRMED":
		return failure("UserNotConfirmedException", "User is not confirmed.")
	case "RESET_REQUIRED":
		return failure("PasswordResetRequiredException", "Password reset required for the user")
	default:
		return failure("NotAuthorizedException", "User cannot authenticate with a password.")
	}
}

func loginFeatures(pool PoolRecord, client ClientRecord) error {
	if value(pool.Data.MfaConfiguration) == "ON" {
		return failure("InvalidParameterException", "MFA authentication is not supported.")
	}
	if pool.Data.DeviceConfiguration != nil {
		return failure("InvalidParameterException", "Device authentication is not supported.")
	}
	return nil
}

func (s *Service) beginAuth(tx Transaction, pool PoolRecord, client ClientRecord, flow string, params api.AuthParametersType, admin bool) (*api.InitiateAuthOutput, error) {
	if !admin && (flow == "ADMIN_USER_PASSWORD_AUTH" || flow == "ADMIN_NO_SRP_AUTH") {
		return nil, failure("InvalidParameterException", "Initiate Auth method not supported.")
	}
	if admin && flow == "USER_PASSWORD_AUTH" {
		return nil, failure("InvalidParameterException", "AdminInitiateAuth does not support USER_PASSWORD_AUTH.")
	}
	switch flow {
	case "USER_PASSWORD_AUTH", "ADMIN_USER_PASSWORD_AUTH", "ADMIN_NO_SRP_AUTH", "USER_SRP_AUTH", "REFRESH_TOKEN_AUTH", "REFRESH_TOKEN":
	default:
		return nil, failure("InvalidParameterException", "Authentication flow "+flow+" is not supported.")
	}
	username := string(params["USERNAME"])
	var user UserRecord
	var userErr error
	if flow != "REFRESH_TOKEN_AUTH" && flow != "REFRESH_TOKEN" && username != "" {
		user, userErr = resolveUser(tx, pool, username)
		if userErr == nil {
			noteUser(tx.Context(), user)
		}
	}
	if (flow == "REFRESH_TOKEN_AUTH" || flow == "REFRESH_TOKEN") && refreshRotationEnabled(client) {
		return nil, failure("UnsupportedOperationException", "This API does not support refresh token rotation")
	}
	if !authFlowEnabled(client, flow) {
		return nil, failure("InvalidParameterException", flow+" flow not enabled for this client")
	}
	if err := loginFeatures(pool, client); err != nil {
		return nil, err
	}
	if params["DEVICE_KEY"] != "" {
		return nil, failure("InvalidParameterException", "Device authentication is not supported.")
	}
	if flow == "REFRESH_TOKEN_AUTH" || flow == "REFRESH_TOKEN" {
		return s.refreshAuth(tx, pool, client, params)
	}
	if username == "" {
		return nil, failure("InvalidParameterException", "Missing required parameter USERNAME")
	}
	if err := checkSecretHash(client, username, string(params["SECRET_HASH"])); err != nil {
		return nil, err
	}
	err := userErr
	if err != nil {
		var missing *awswire.Error
		if value(client.Data.PreventUserExistenceErrors) == "ENABLED" && (errors.Is(err, ErrNotFound) || errors.As(err, &missing) && missing.Code == "UserNotFoundException") {
			if flow == "USER_SRP_AUTH" {
				return s.missingUserSRP(tx, pool, canonicalUsername(pool, username), string(params["SRP_A"]))
			}
			return nil, failure("NotAuthorizedException", "Incorrect username or password.")
		}
		return nil, err
	}
	if err := s.authUserStatus(user); err != nil {
		return nil, err
	}
	if flow == "USER_SRP_AUTH" {
		return s.startSRP(tx, pool, client, user, string(params["SRP_A"]))
	}
	password := string(params["PASSWORD"])
	if password == "" {
		return nil, failure("InvalidParameterException", "Missing required parameter PASSWORD")
	}
	matches, err := matchesPassword(pool.Key, user.Key.Username, password, user.Password)
	if err != nil {
		return nil, err
	}
	if !matches {
		return nil, failure("NotAuthorizedException", "Incorrect username or password.")
	}
	return s.passwordAccepted(tx, pool, client, user)
}

func (s *Service) passwordAccepted(tx Transaction, pool PoolRecord, client ClientRecord, user UserRecord) (*api.InitiateAuthOutput, error) {
	if value(user.Data.UserStatus) == "FORCE_CHANGE_PASSWORD" {
		token, err := randomToken(96)
		if err != nil {
			return nil, err
		}
		// Bind the proof to this password generation. An administrative reset must
		// not let an already-issued challenge authorize a later credential.
		credential := sha256.Sum256(user.Password.Verifier)
		challenge := ChallengeRecord{Key: ChallengeKey{PoolKey: pool.Key, Token: token}, ClientID: client.Key.ID, Username: user.Key.Username, Kind: "NEW_PASSWORD_REQUIRED", Expires: s.clock.Now().Add(challengeDuration(client)), SRPPrivate: credential[:]}
		required := make([]string, 0)
		for _, attribute := range pool.Data.SchemaAttributes {
			name := value(attribute.Name)
			if name != "sub" && attribute.Required != nil && bool(*attribute.Required) && userAttribute(user, name) == "" {
				required = append(required, "userAttributes."+name)
			}
		}
		attributes := make(map[string]string)
		for _, attribute := range readableAttributes(user, client) {
			if name := value(attribute.Name); name != "sub" {
				attributes[name] = value(attribute.Value)
			}
		}
		requiredJSON, err := json.Marshal(required)
		if err != nil {
			return nil, err
		}
		attributesJSON, err := json.Marshal(attributes)
		if err != nil {
			return nil, err
		}
		if err := tx.PutChallenge(challenge); err != nil {
			return nil, err
		}
		return &api.InitiateAuthOutput{ChallengeName: str[api.ChallengeNameType](challenge.Kind), Session: str[api.SessionType](token), ChallengeParameters: api.ChallengeParametersType{"USER_ID_FOR_SRP": api.StringType(user.Key.Username), "requiredAttributes": api.StringType(requiredJSON), "userAttributes": api.StringType(attributesJSON)}}, nil
	}
	result, err := s.newSession(tx, pool, client, user)
	if err != nil {
		return nil, err
	}
	return &api.InitiateAuthOutput{AuthenticationResult: result, ChallengeParameters: api.ChallengeParametersType{}}, nil
}

func (s *Service) respondToAuthChallenge(tx Transaction, input *api.RespondToAuthChallengeInput) (*api.RespondToAuthChallengeOutput, error) {
	pool, client, err := s.authClient(tx, "RespondToAuthChallenge", "", value(input.ClientId))
	if err != nil {
		return nil, err
	}
	out, err := s.completeChallenge(tx, pool, client, value(input.ChallengeName), value(input.Session), input.ChallengeResponses)
	if err != nil {
		return nil, err
	}
	return &api.RespondToAuthChallengeOutput{AuthenticationResult: out.AuthenticationResult, ChallengeName: out.ChallengeName, ChallengeParameters: out.ChallengeParameters, Session: out.Session}, nil
}

func (s *Service) adminRespondToAuthChallenge(tx Transaction, input *api.AdminRespondToAuthChallengeInput) (*api.AdminRespondToAuthChallengeOutput, error) {
	pool, client, err := s.authClient(tx, "AdminRespondToAuthChallenge", value(input.UserPoolId), value(input.ClientId))
	if err != nil {
		return nil, err
	}
	out, err := s.completeChallenge(tx, pool, client, value(input.ChallengeName), value(input.Session), input.ChallengeResponses)
	if err != nil {
		return nil, err
	}
	return &api.AdminRespondToAuthChallengeOutput{AuthenticationResult: out.AuthenticationResult, ChallengeName: out.ChallengeName, ChallengeParameters: out.ChallengeParameters, Session: out.Session}, nil
}

func (s *Service) completeChallenge(tx Transaction, pool PoolRecord, client ClientRecord, kind, token string, responses api.ChallengeResponsesType) (*api.InitiateAuthOutput, error) {
	if kind != "PASSWORD_VERIFIER" && kind != "NEW_PASSWORD_REQUIRED" {
		return nil, failure("InvalidParameterException", "Authentication challenge "+kind+" is not supported.")
	}
	if err := loginFeatures(pool, client); err != nil {
		return nil, err
	}
	if responses["DEVICE_KEY"] != "" {
		return nil, failure("InvalidParameterException", "Device authentication is not supported.")
	}
	username := string(responses["USERNAME"])
	if username == "" {
		return nil, failure("InvalidParameterException", "Missing required parameter USERNAME")
	}
	user, userErr := tx.User(UserKey{PoolKey: pool.Key, Username: username})
	if userErr == nil {
		noteUser(tx.Context(), user)
	}
	if err := checkSecretHash(client, username, string(responses["SECRET_HASH"])); err != nil {
		return nil, err
	}
	if kind == "PASSWORD_VERIFIER" {
		token = string(responses["PASSWORD_CLAIM_SECRET_BLOCK"])
	}
	if token == "" {
		return nil, failure("NotAuthorizedException", "Invalid session for the user.")
	}
	challenge, err := tx.Challenge(ChallengeKey{PoolKey: pool.Key, Token: token})
	if errors.Is(err, ErrNotFound) {
		if kind == "PASSWORD_VERIFIER" {
			return nil, failure("NotAuthorizedException", "Incorrect username or password.")
		}
		return nil, failure("NotAuthorizedException", "Invalid session for the user, session can only be used once.")
	}
	if err != nil {
		return nil, err
	}
	if challenge.ClientID != client.Key.ID || challenge.Kind != kind || challenge.Username != username || !s.clock.Now().Before(challenge.Expires) {
		return nil, failure("NotAuthorizedException", "Invalid session for the user.")
	}
	if errors.Is(userErr, ErrNotFound) {
		return nil, failure("UserNotFoundException", "User does not exist.")
	}
	if userErr != nil {
		return nil, userErr
	}
	if err := s.authUserStatus(user); err != nil {
		return nil, err
	}
	if kind == "PASSWORD_VERIFIER" {
		if !authFlowEnabled(client, "USER_SRP_AUTH") {
			return nil, failure("InvalidParameterException", "USER_SRP_AUTH flow not enabled for this client")
		}
		if err := s.verifySRP(pool, user, challenge, responses); err != nil {
			return nil, err
		}
	} else {
		credential := sha256.Sum256(user.Password.Verifier)
		if value(user.Data.UserStatus) != "FORCE_CHANGE_PASSWORD" || !hmac.Equal(credential[:], challenge.SRPPrivate) {
			return nil, failure("NotAuthorizedException", "Invalid session for the user.")
		}
		password := string(responses["NEW_PASSWORD"])
		if password == "" {
			return nil, failure("InvalidParameterException", "Missing required parameter NEW_PASSWORD")
		}
		if err := validatePassword(pool, password); err != nil {
			return nil, err
		}
		attributes := make(api.AttributeListType, 0)
		for name, v := range responses {
			if attribute, ok := strings.CutPrefix(string(name), "userAttributes."); ok {
				schema := schemaAttribute(pool, attribute)
				if schema != nil && schema.Required != nil && bool(*schema.Required) && userAttribute(user, attribute) != "" && userAttribute(user, attribute) != string(v) {
					return nil, failure("InvalidParameterException", "Cannot modify an existing required attribute in NEW_PASSWORD_REQUIRED.")
				}
				attributes = append(attributes, api.AttributeType{Name: str[api.AttributeNameType](attribute), Value: str[api.AttributeValueType](string(v))})
			}
		}
		if err := setUserAttributes(pool, &user, attributes, &client); err != nil {
			return nil, err
		}
		for _, attribute := range pool.Data.SchemaAttributes {
			if attribute.Required != nil && bool(*attribute.Required) && userAttribute(user, value(attribute.Name)) == "" {
				return nil, failure("InvalidParameterException", "Missing required attribute "+value(attribute.Name))
			}
		}
		if err := ensureUserAliases(tx, pool, &user, false); err != nil {
			return nil, err
		}
		user.Password, err = makePasswordVerifier(pool.Key, user.Key.Username, password)
		if err != nil {
			return nil, err
		}
		user.PasswordExpires = nil
		user.Data.UserStatus = str[api.UserStatusType]("CONFIRMED")
		user.Data.UserLastModifiedDate = ptr(s.clock.Now().UTC())
		if err := tx.PutUser(user); err != nil {
			return nil, err
		}
	}
	if err := tx.DeleteChallenge(challenge.Key); err != nil {
		return nil, err
	}
	return s.passwordAccepted(tx, pool, client, user)
}

func (s *Service) globalSignOut(tx Transaction, input *api.GlobalSignOutInput) (*api.GlobalSignOutOutput, error) {
	_, _, user, _, err := s.accessUser(tx, value(input.AccessToken))
	if err != nil {
		return nil, err
	}
	if err := tx.RevokeUserSessions(user.Key); err != nil {
		return nil, err
	}
	return &api.GlobalSignOutOutput{}, nil
}

func (s *Service) adminUserGlobalSignOut(tx Transaction, input *api.AdminUserGlobalSignOutInput) (*api.AdminUserGlobalSignOutOutput, error) {
	pool, err := s.adminPool(tx, "AdminUserGlobalSignOut", value(input.UserPoolId))
	if err != nil {
		return nil, err
	}
	user, err := resolveUser(tx, pool, value(input.Username))
	if err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	if err := tx.RevokeUserSessions(user.Key); err != nil {
		return nil, err
	}
	return &api.AdminUserGlobalSignOutOutput{}, nil
}

func poolIssuerURL(key PoolKey, endpoint string) string {
	if endpoint != "" {
		return strings.TrimRight(endpoint, "/") + "/" + key.ID
	}
	domain := "amazonaws.com"
	switch key.Partition {
	case "aws-cn":
		domain = "amazonaws.com.cn"
	case "aws-eusc":
		domain = "amazonaws.eu"
	case "aws-iso":
		domain = "c2s.ic.gov"
	case "aws-iso-b":
		domain = "sc2s.sgov.gov"
	case "aws-iso-e":
		domain = "cloud.adc-e.uk"
	case "aws-iso-f":
		domain = "csp.hci.ic.gov"
	}
	return "https://cognito-idp." + key.Region + "." + domain + "/" + key.ID
}
