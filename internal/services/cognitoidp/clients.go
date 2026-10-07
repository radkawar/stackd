package cognitoidp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"slices"
	"sort"
	"strings"

	api "stackd/internal/awsapi/cognitoidp"
)

func (s *Service) createUserPoolClient(tx Transaction, in *api.CreateUserPoolClientInput) (*api.CreateUserPoolClientOutput, error) {
	pool, err := s.adminPool(tx, "CreateUserPoolClient", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	data, err := clientConfiguration(tx, pool, in)
	if err != nil {
		return nil, err
	}
	id, err := controlID(13)
	if err != nil {
		return nil, err
	}
	data.ClientId = str[api.ClientIdType](id)
	data.UserPoolId = pool.Data.Id
	now := s.clock.Now()
	data.CreationDate = &now
	data.LastModifiedDate = &now
	if in.GenerateSecret != nil && bool(*in.GenerateSecret) {
		var secret [32]byte
		if _, err = rand.Read(secret[:]); err != nil {
			return nil, err
		}
		data.ClientSecret = str[api.ClientSecretType](hex.EncodeToString(secret[:]))
	}
	client := ClientRecord{Key: ClientKey{PoolKey: pool.Key, ID: id}, Data: data}
	if err = tx.PutClient(client); err != nil {
		return nil, err
	}
	return &api.CreateUserPoolClientOutput{UserPoolClient: &data}, nil
}

// OAuth configuration is persisted independently of the external authorization
// endpoints. Configuring a client does not execute a federated sign-in.
func clientConfiguration(tx Transaction, pool PoolRecord, in *api.CreateUserPoolClientInput) (api.UserPoolClientType, error) {
	var d api.UserPoolClientType
	invalid := func(message string) (api.UserPoolClientType, error) {
		return d, failure("InvalidParameterException", message)
	}
	if !validControlName(value(in.ClientName)) {
		return invalid("Invalid app client name.")
	}
	if in.ClientSecret != nil {
		return invalid("Importing app client secrets is not supported.")
	}
	if err := validateClientOAuth(in); err != nil {
		return d, err
	}
	if in.AnalyticsConfiguration != nil || (in.EnablePropagateAdditionalUserContextData != nil && bool(*in.EnablePropagateAdditionalUserContextData)) {
		return invalid("Analytics and advanced security context propagation are not supported.")
	}
	providers := map[string]bool{}
	for _, provider := range in.SupportedIdentityProviders {
		name := string(provider)
		if providers[name] {
			return invalid("Duplicate identity provider: " + name)
		}
		providers[name] = true
		if name != "COGNITO" {
			if _, err := tx.Provider(ProviderKey{PoolKey: pool.Key, Name: name}); errors.Is(err, ErrNotFound) {
				return invalid("Identity provider " + name + " does not exist in this user pool.")
			} else if err != nil {
				return d, err
			}
		}
	}
	rotation := in.RefreshTokenRotation
	if rotation != nil {
		config := *rotation
		switch value(config.Feature) {
		case "ENABLED":
			if value(pool.Data.UserPoolTier) == "LITE" {
				return d, failure("FeatureUnavailableInTierException", "The following features need to be disabled for the LITE pricing tier configured: Refresh Token Rotation")
			}
			if slices.Contains(in.ExplicitAuthFlows, api.ExplicitAuthFlowsType("ALLOW_REFRESH_TOKEN_AUTH")) {
				return invalid("ALLOW_REFRESH_TOKEN_AUTH is not a permitted ExplicitAuthFlow when refresh token rotation is enabled.")
			}
		case "DISABLED":
			config.RetryGracePeriodSeconds = nil
		default:
			return invalid("Invalid refresh token rotation feature.")
		}
		if config.RetryGracePeriodSeconds == nil {
			config.RetryGracePeriodSeconds = ptr(api.RetryGracePeriodSecondsType(0))
		}
		rotation = &config
	}
	seen := map[api.ExplicitAuthFlowsType]bool{}
	legacy, modern := false, false
	for _, flow := range in.ExplicitAuthFlows {
		if seen[flow] {
			return invalid("Duplicate explicit authentication flow.")
		}
		seen[flow] = true
		if strings.HasPrefix(string(flow), "ALLOW_") {
			modern = true
		} else {
			legacy = true
		}
		switch flow {
		case "ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH", "USER_PASSWORD_AUTH", "ADMIN_NO_SRP_AUTH":
		default:
			return invalid("Requested explicit authentication flow is not supported.")
		}
	}
	if modern && legacy {
		return invalid("Legacy and ALLOW_ authentication flows cannot be combined.")
	}
	if in.AuthSessionValidity != nil && (*in.AuthSessionValidity < 3 || *in.AuthSessionValidity > 15) {
		return invalid("AuthSessionValidity must be between 3 and 15 minutes.")
	}
	if in.PreventUserExistenceErrors != nil && value(in.PreventUserExistenceErrors) != "LEGACY" && value(in.PreventUserExistenceErrors) != "ENABLED" {
		return invalid("Invalid PreventUserExistenceErrors value.")
	}
	for _, permissions := range []api.ClientPermissionListType{in.ReadAttributes, in.WriteAttributes} {
		seen := map[string]bool{}
		for _, a := range permissions {
			name := string(a)
			if schemaAttribute(pool, name) == nil || strings.HasPrefix(name, "dev:") || seen[name] {
				return invalid("Invalid attribute permission: " + name)
			}
			seen[name] = true
		}
	}
	for _, a := range in.WriteAttributes {
		if a == "sub" || a == "email_verified" || a == "phone_number_verified" {
			return invalid("Invalid write attribute permission: " + string(a))
		}
	}
	if len(in.WriteAttributes) > 0 {
		for _, a := range pool.Data.SchemaAttributes {
			name := value(a.Name)
			if name != "sub" && a.Required != nil && bool(*a.Required) && !slices.Contains(in.WriteAttributes, api.ClientPermissionType(name)) {
				return invalid("WriteAttributes must include required attributes.")
			}
		}
	}
	units := in.TokenValidityUnits
	if units == nil {
		units = &api.TokenValidityUnitsType{}
	}
	if in.AccessTokenValidity != nil {
		if err := validateTokenValidity(int64(*in.AccessTokenValidity), value(units.AccessToken), "hours", 300, 86400); err != nil {
			return d, err
		}
	}
	if in.IdTokenValidity != nil {
		if err := validateTokenValidity(int64(*in.IdTokenValidity), value(units.IdToken), "hours", 300, 86400); err != nil {
			return d, err
		}
	}
	refresh := in.RefreshTokenValidity
	if refresh == nil || *refresh == 0 {
		days30 := api.RefreshTokenValidityType(30)
		switch value(units.RefreshToken) {
		case "seconds":
			days30 = 2592000
		case "minutes":
			days30 = 43200
		case "hours":
			days30 = 720
		}
		refresh = &days30
	}
	if in.RefreshTokenValidity != nil && *in.RefreshTokenValidity != 0 {
		if err := validateTokenValidity(int64(*refresh), value(units.RefreshToken), "days", 3600, 315360000); err != nil {
			return d, err
		}
	}
	for _, unit := range []*api.TimeUnitsType{units.AccessToken, units.IdToken, units.RefreshToken} {
		if unit != nil && value(unit) != "seconds" && value(unit) != "minutes" && value(unit) != "hours" && value(unit) != "days" {
			return invalid("Invalid token validity unit.")
		}
	}
	d = api.UserPoolClientType{
		ClientName: in.ClientName, AccessTokenValidity: in.AccessTokenValidity, IdTokenValidity: in.IdTokenValidity, RefreshTokenValidity: refresh, TokenValidityUnits: units,
		AuthSessionValidity: in.AuthSessionValidity, EnableTokenRevocation: in.EnableTokenRevocation, ExplicitAuthFlows: in.ExplicitAuthFlows, PreventUserExistenceErrors: in.PreventUserExistenceErrors,
		ReadAttributes: in.ReadAttributes, WriteAttributes: in.WriteAttributes, SupportedIdentityProviders: in.SupportedIdentityProviders, RefreshTokenRotation: rotation,
		AllowedOAuthFlows: in.AllowedOAuthFlows, AllowedOAuthScopes: in.AllowedOAuthScopes, CallbackURLs: in.CallbackURLs, LogoutURLs: in.LogoutURLs, DefaultRedirectURI: in.DefaultRedirectURI,
		AllowedOAuthFlowsUserPoolClient: in.AllowedOAuthFlowsUserPoolClient, EnablePropagateAdditionalUserContextData: ptr(api.WrappedBooleanType(false)),
	}
	if d.AllowedOAuthFlowsUserPoolClient == nil {
		d.AllowedOAuthFlowsUserPoolClient = ptr(api.BooleanType(false))
	}
	if d.AuthSessionValidity == nil {
		d.AuthSessionValidity = ptr(api.AuthSessionValidityType(3))
	}
	if d.EnableTokenRevocation == nil {
		d.EnableTokenRevocation = ptr(api.WrappedBooleanType(true))
	}
	return d, nil
}

// AWS CreateUserPoolClient defines the configuration contract; authorization
// endpoint execution is a separate surface and is not synthesized here.
func validateClientOAuth(in *api.CreateUserPoolClientInput) error {
	invalid := func(message string) error {
		return failure("InvalidParameterException", message)
	}
	enabled := in.AllowedOAuthFlowsUserPoolClient != nil && bool(*in.AllowedOAuthFlowsUserPoolClient)
	if !enabled && (len(in.AllowedOAuthFlows) > 0 || len(in.AllowedOAuthScopes) > 0 || len(in.CallbackURLs) > 0 || len(in.LogoutURLs) > 0 || in.DefaultRedirectURI != nil) {
		return invalid("AllowedOAuthFlowsUserPoolClient must be true to configure OAuth features.")
	}
	if len(in.AllowedOAuthFlows) > 3 || len(in.AllowedOAuthScopes) > 50 || len(in.CallbackURLs) > 100 || len(in.LogoutURLs) > 100 {
		return invalid("OAuth configuration exceeds the permitted list size.")
	}
	flows := map[string]bool{}
	for _, flow := range in.AllowedOAuthFlows {
		name := string(flow)
		if flows[name] || (name != "code" && name != "implicit" && name != "client_credentials") {
			return invalid("Invalid or duplicate OAuth flow: " + name)
		}
		flows[name] = true
	}
	if flows["client_credentials"] {
		if len(flows) != 1 {
			return invalid("client_credentials must be the only allowed OAuth flow.")
		}
		if in.GenerateSecret == nil || !bool(*in.GenerateSecret) {
			return invalid("client_credentials requires a client secret.")
		}
	}
	if (flows["code"] || flows["implicit"]) && len(in.CallbackURLs) == 0 {
		return invalid("CallbackURLs are required for code and implicit OAuth flows.")
	}
	scopes := map[string]bool{}
	for _, scope := range in.AllowedOAuthScopes {
		name := string(scope)
		if scopes[name] {
			return invalid("Duplicate OAuth scope: " + name)
		}
		scopes[name] = true
		switch name {
		case "openid", "email", "phone", "profile", "aws.cognito.signin.user.admin":
			if flows["client_credentials"] {
				return invalid("client_credentials permits only custom resource server scopes.")
			}
		default:
			// No resource servers exist on the native surface yet, so a custom
			// scope cannot resolve to a registered resource server.
			return failure("ScopeDoesNotExistException", "OAuth scope does not exist: "+name)
		}
	}
	if (scopes["email"] || scopes["phone"] || scopes["profile"]) && !scopes["openid"] {
		return invalid("The email, phone, and profile scopes require openid.")
	}
	for _, urls := range []api.CallbackURLsListType{in.CallbackURLs, api.CallbackURLsListType(in.LogoutURLs)} {
		seen := map[string]bool{}
		for _, raw := range urls {
			text := string(raw)
			u, err := url.Parse(text)
			if err != nil || len(text) == 0 || len(text) > 1024 || strings.ContainsAny(text, " \t\r\n#") || u.Scheme == "" || u.User != nil || seen[text] {
				return invalid("Invalid or duplicate redirect URL: " + text)
			}
			if (u.Scheme == "https" || u.Scheme == "http") && u.Host == "" {
				return invalid("Redirect URLs must be absolute.")
			}
			if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
				return invalid("HTTP redirect URLs are permitted only for localhost loopback addresses.")
			}
			seen[text] = true
		}
	}
	if in.DefaultRedirectURI != nil && !slices.Contains(in.CallbackURLs, api.RedirectUrlType(*in.DefaultRedirectURI)) {
		return invalid("DefaultRedirectURI must be in CallbackURLs.")
	}
	return nil
}
func validateTokenValidity(n int64, unit, defaultUnit string, min, max int64) error {
	if unit == "" {
		unit = defaultUnit
	}
	multiplier := int64(0)
	switch unit {
	case "seconds":
		multiplier = 1
	case "minutes":
		multiplier = 60
	case "hours":
		multiplier = 3600
	case "days":
		multiplier = 86400
	}
	if multiplier == 0 || n < 1 || n > max/multiplier || n*multiplier < min {
		return failure("InvalidParameterException", "Invalid token validity duration.")
	}
	return nil
}

func adminClient(tx Transaction, pool PoolRecord, id string) (ClientRecord, error) {
	client, err := tx.Client(ClientKey{PoolKey: pool.Key, ID: id})
	if errors.Is(err, ErrNotFound) {
		return ClientRecord{}, failure("ResourceNotFoundException", "User pool client "+id+" does not exist.")
	}
	return client, err
}
func (s *Service) describeUserPoolClient(tx Transaction, in *api.DescribeUserPoolClientInput) (*api.DescribeUserPoolClientOutput, error) {
	pool, err := s.adminPool(tx, "DescribeUserPoolClient", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	client, err := adminClient(tx, pool, value(in.ClientId))
	if err != nil {
		return nil, err
	}
	return &api.DescribeUserPoolClientOutput{UserPoolClient: &client.Data}, nil
}
func (s *Service) updateUserPoolClient(tx Transaction, in *api.UpdateUserPoolClientInput) (*api.UpdateUserPoolClientOutput, error) {
	pool, err := s.adminPool(tx, "UpdateUserPoolClient", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	client, err := adminClient(tx, pool, value(in.ClientId))
	if err != nil {
		return nil, err
	}
	config := api.CreateUserPoolClientInput{
		ClientName: in.ClientName, AccessTokenValidity: in.AccessTokenValidity, IdTokenValidity: in.IdTokenValidity, RefreshTokenValidity: in.RefreshTokenValidity, TokenValidityUnits: in.TokenValidityUnits,
		AuthSessionValidity: in.AuthSessionValidity, EnableTokenRevocation: in.EnableTokenRevocation, ExplicitAuthFlows: in.ExplicitAuthFlows, PreventUserExistenceErrors: in.PreventUserExistenceErrors,
		ReadAttributes: in.ReadAttributes, WriteAttributes: in.WriteAttributes, SupportedIdentityProviders: in.SupportedIdentityProviders, RefreshTokenRotation: in.RefreshTokenRotation,
		AllowedOAuthFlows: in.AllowedOAuthFlows, AllowedOAuthScopes: in.AllowedOAuthScopes, AllowedOAuthFlowsUserPoolClient: in.AllowedOAuthFlowsUserPoolClient,
		AnalyticsConfiguration: in.AnalyticsConfiguration, CallbackURLs: in.CallbackURLs, LogoutURLs: in.LogoutURLs, DefaultRedirectURI: in.DefaultRedirectURI, EnablePropagateAdditionalUserContextData: in.EnablePropagateAdditionalUserContextData,
	}
	// A client secret is immutable, but client_credentials admission still
	// requires it when replacing the mutable configuration.
	config.GenerateSecret = ptr(api.GenerateSecret(client.Data.ClientSecret != nil))
	if config.ClientName == nil {
		config.ClientName = client.Data.ClientName
	}
	data, err := clientConfiguration(tx, pool, &config)
	if err != nil {
		return nil, err
	}
	data.ClientId = client.Data.ClientId
	data.UserPoolId = client.Data.UserPoolId
	data.ClientSecret = client.Data.ClientSecret
	data.CreationDate = client.Data.CreationDate
	now := s.clock.Now()
	data.LastModifiedDate = &now
	client.Data = data
	if err = tx.PutClient(client); err != nil {
		return nil, err
	}
	return &api.UpdateUserPoolClientOutput{UserPoolClient: &data}, nil
}
func (s *Service) deleteUserPoolClient(tx Transaction, in *api.DeleteUserPoolClientInput) (*api.DeleteUserPoolClientOutput, error) {
	pool, err := s.adminPool(tx, "DeleteUserPoolClient", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	client, err := adminClient(tx, pool, value(in.ClientId))
	if err != nil {
		return nil, err
	}
	if err = tx.DeleteClient(client.Key); err != nil {
		return nil, err
	}
	return &api.DeleteUserPoolClientOutput{}, nil
}
func (s *Service) listUserPoolClients(tx Transaction, in *api.ListUserPoolClientsInput) (*api.ListUserPoolClientsOutput, error) {
	pool, err := s.adminPool(tx, "ListUserPoolClients", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	limit := 60
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	if limit < 1 || limit > 60 {
		return nil, failure("InvalidParameterException", "MaxResults must be between 1 and 60.")
	}
	binding := "clients:" + pool.Key.ARN()
	cursor, err := pageCursor(value(in.NextToken), binding)
	if err != nil {
		return nil, err
	}
	clients, err := tx.Clients(pool.Key)
	if err != nil {
		return nil, err
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].Key.ID < clients[j].Key.ID })
	out := &api.ListUserPoolClientsOutput{UserPoolClients: api.UserPoolClientListType{}}
	for _, client := range clients {
		if client.Key.ID <= cursor {
			continue
		}
		if len(out.UserPoolClients) == limit {
			out.NextToken = str[api.PaginationKey](nextPage(binding, value(out.UserPoolClients[len(out.UserPoolClients)-1].ClientId)))
			break
		}
		out.UserPoolClients = append(out.UserPoolClients, api.UserPoolClientDescription{ClientId: client.Data.ClientId, ClientName: client.Data.ClientName, UserPoolId: client.Data.UserPoolId})
	}
	return out, nil
}
