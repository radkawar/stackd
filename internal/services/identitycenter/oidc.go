package identitycenter

import (
	"crypto/subtle"
	"errors"
	"net/url"
	"slices"
	api "stackd/internal/awsapi/ssooidc"
	"stackd/internal/awswire"
	"strings"
	"time"
)

const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

func (s *Service) registerOIDC() {
	register(s, "ssooidc", "RegisterClient", s.registerClient)
	register(s, "ssooidc", "StartDeviceAuthorization", s.startDevice)
	register(s, "ssooidc", "CreateToken", s.createToken)
}

// The issuer identifies an instance, not the local transport endpoint. Current
// AWS CLI versions require an AWS-owned issuer/start URL before OIDC discovery.
func issuerHost(partition string) string {
	switch partition {
	case "aws":
		return "identitycenter.amazonaws.com"
	case "aws-cn":
		return "identitycenter.amazonaws.com.cn"
	case "aws-us-gov":
		return "identitycenter.us-gov.amazonaws.com"
	default:
		return ""
	}
}

func (s *Service) registerClient(tx Transaction, in *api.RegisterClientInput) (*api.RegisterClientOutput, error) {
	if value(in.ClientType) != "public" || value(in.ClientName) == "" {
		return nil, oauthError("InvalidClientMetadataException", "invalid_client_metadata", "A named public client is required.", 400)
	}
	if in.EntitledApplicationArn != nil {
		// TODO: Application-entitled registration requires the application owner.
		return nil, oauthError("InvalidClientMetadataException", "invalid_client_metadata", "Application-specific registration is not implemented.", 400)
	}
	grants := []string{}
	for _, g := range in.GrantTypes {
		if string(g) != deviceGrant && string(g) != "refresh_token" && string(g) != "authorization_code" {
			return nil, oauthError("InvalidClientMetadataException", "invalid_client_metadata", "The requested grant is not supported.", 400)
		}
		if !slices.Contains(grants, string(g)) {
			grants = append(grants, string(g))
		}
	}
	if len(grants) == 0 {
		grants = []string{deviceGrant, "refresh_token"}
	}
	redirects := []string{}
	for _, uri := range in.RedirectUris {
		if !validRedirectURI(string(uri)) {
			return nil, oauthError("InvalidRedirectUriException", "invalid_redirect_uri", "Redirect URIs must be absolute, without fragments or user information.", 400)
		}
		if !slices.Contains(redirects, string(uri)) {
			redirects = append(redirects, string(uri))
		}
	}
	if slices.Contains(grants, "authorization_code") && len(redirects) == 0 {
		return nil, oauthError("InvalidRedirectUriException", "invalid_redirect_uri", "Authorization code clients require a registered redirect URI.", 400)
	}
	scope := scopeFor(tx.Context())
	issuer := value(in.IssuerUrl)
	if issuer != "" {
		if _, e := s.issuerInstance(tx, scope.Partition, scope.Region, issuer); e != nil {
			return nil, e
		}
	}
	scopes := []string{}
	for _, scope := range in.Scopes {
		if scope != "sso:account:access" {
			return nil, oauthError("InvalidScopeException", "invalid_scope", "The requested scope is not supported.", 400)
		}
		if !slices.Contains(scopes, string(scope)) {
			scopes = append(scopes, string(scope))
		}
	}
	if len(scopes) == 0 {
		scopes = []string{"sso:account:access"}
	}
	id, e := randomToken()
	if e != nil {
		return nil, e
	}
	secret, e := randomToken()
	if e != nil {
		return nil, e
	}
	now := s.clock.Now()
	expires := now.Add(90 * 24 * time.Hour)
	if e = tx.PutClient(Client{ID: id, SecretHash: tokenHash(secret), Name: value(in.ClientName), Region: scope.Region, Partition: scope.Partition, Created: now, Expires: expires, Scopes: scopes, GrantTypes: grants, RedirectURIs: redirects, IssuerURL: issuer}); e != nil {
		return nil, e
	}
	return &api.RegisterClientOutput{ClientId: new(api.ClientId(id)), ClientSecret: new(api.ClientSecret(secret)), ClientIdIssuedAt: new(api.LongTimeStampType(now.Unix())), ClientSecretExpiresAt: new(api.LongTimeStampType(expires.Unix())), AuthorizationEndpoint: new(api.URI(s.endpoint + AuthorizePath)), TokenEndpoint: new(api.URI(s.endpoint + "/token"))}, nil
}
func (s *Service) client(r Reader, id, secret string) (Client, error) {
	c, e := r.Client(id)
	scope := scopeFor(r.Context())
	if e != nil || secret == "" || !s.clock.Now().Before(c.Expires) || c.Region != scope.Region || c.Partition != scope.Partition || subtle.ConstantTimeCompare([]byte(c.SecretHash), []byte(tokenHash(secret))) != 1 {
		return Client{}, oauthError("InvalidClientException", "invalid_client", "The client credentials are invalid or expired.", 401)
	}
	return c, nil
}
func (s *Service) startDevice(tx Transaction, in *api.StartDeviceAuthorizationInput) (*api.StartDeviceAuthorizationOutput, error) {
	client, e := s.client(tx, value(in.ClientId), value(in.ClientSecret))
	if e != nil {
		return nil, e
	}
	if !slices.Contains(client.GrantTypes, deviceGrant) {
		return nil, oauthError("UnauthorizedClientException", "unauthorized_client", "This client is not registered for device authorization.", 400)
	}
	if client.IssuerURL != "" && client.IssuerURL != value(in.StartUrl) {
		return nil, oauthError("InvalidRequestException", "invalid_request", "The start URL differs from the registered issuer.", 400)
	}
	start, e := url.Parse(value(in.StartUrl))
	if e != nil || start.Scheme != "https" || start.Host != issuerHost(client.Partition) || start.User != nil || start.RawQuery != "" || start.Fragment != "" || !strings.HasPrefix(start.Path, "/ssoins-") {
		return nil, oauthError("InvalidRequestException", "invalid_request", "The start URL must be the Identity Center issuer URL for this partition.", 400)
	}
	id := strings.TrimPrefix(start.Path, "/")
	instance, e := tx.Instance("arn:" + client.Partition + ":sso:::instance/" + id)
	if e != nil || instance.Region != client.Region {
		return nil, oauthError("InvalidRequestException", "invalid_request", "The start URL does not identify an instance in this Region.", 400)
	}
	raw, e := randomToken()
	if e != nil {
		return nil, e
	}
	short, e := randomHex(4)
	if e != nil {
		return nil, e
	}
	userCode := strings.ToUpper(short[:4] + "-" + short[4:])
	now := s.clock.Now()
	if e = tx.PutDevice(Device{CodeHash: tokenHash(raw), UserCode: userCode, ClientID: client.ID, InstanceARN: instance.ARN, State: "PENDING", Created: now, Expires: now.Add(10 * time.Minute), Interval: 5}); e != nil {
		return nil, e
	}
	uri := s.endpoint + AuthorizationPath + "device"
	return &api.StartDeviceAuthorizationOutput{DeviceCode: new(api.DeviceCode(raw)), UserCode: new(api.UserCode(userCode)), ExpiresIn: new(api.ExpirationInSeconds(600)), Interval: new(api.IntervalInSeconds(5)), VerificationUri: new(api.URI(uri)), VerificationUriComplete: new(api.URI(uri + "?user_code=" + url.QueryEscape(userCode)))}, nil
}
func (s *Service) createToken(tx Transaction, in *api.CreateTokenInput) (*api.CreateTokenOutput, error) {
	client, e := s.client(tx, value(in.ClientId), value(in.ClientSecret))
	if e != nil {
		return nil, e
	}
	grant := value(in.GrantType)
	if grant != deviceGrant && grant != "refresh_token" && grant != "authorization_code" {
		return nil, oauthError("UnsupportedGrantTypeException", "unsupported_grant_type", "Use authorization_code, device authorization or refresh_token.", 400)
	}
	if !slices.Contains(client.GrantTypes, grant) {
		return nil, oauthError("UnauthorizedClientException", "unauthorized_client", "This client is not registered for this grant.", 400)
	}
	if grant == "refresh_token" {
		return s.refreshToken(tx, client, value(in.RefreshToken))
	}
	if grant == "authorization_code" {
		return s.exchangeAuthorization(tx, client, in)
	}
	device, e := tx.Device(tokenHash(value(in.DeviceCode)))
	if e != nil || value(in.DeviceCode) == "" || device.ClientID != client.ID {
		return nil, oauthError("InvalidGrantException", "invalid_grant", "The device code is invalid.", 400)
	}
	now := s.clock.Now()
	if !now.Before(device.Expires) {
		return nil, oauthError("ExpiredTokenException", "expired_token", "The device code has expired.", 400)
	}
	if device.State == "CONSUMED" {
		return nil, oauthError("InvalidGrantException", "invalid_grant", "The device code has already been redeemed.", 400)
	}
	if device.State == "DENIED" {
		return nil, oauthError("AccessDeniedException", "access_denied", "The user denied authorization.", 400)
	}
	if !device.LastPoll.IsZero() && now.Before(device.LastPoll.Add(time.Duration(device.Interval)*time.Second)) {
		device.Interval += 5
		device.LastPoll = now
		if e = tx.PutDevice(device); e != nil {
			return nil, e
		}
		return nil, &committedRejection{oauthError("SlowDownException", "slow_down", "Poll no more frequently than the device interval.", 400)}
	}
	device.LastPoll = now
	if device.State != "AUTHORIZED" {
		if e = tx.PutDevice(device); e != nil {
			return nil, e
		}
		return nil, &committedRejection{oauthError("AuthorizationPendingException", "authorization_pending", "User authorization is pending.", 400)}
	}
	instance, e := tx.Instance(device.InstanceARN)
	if e != nil {
		return nil, oauthError("InvalidGrantException", "invalid_grant", "The instance is no longer available.", 400)
	}
	if e = s.currentUser(tx, instance, device.UserID); e != nil {
		return nil, oauthError("AccessDeniedException", "access_denied", "The directory user is no longer available.", 400)
	}
	sessionID, e := randomToken()
	if e != nil {
		return nil, e
	}
	refresh, e := randomToken()
	if e != nil {
		return nil, e
	}
	session := Session{ID: sessionID, FamilyID: sessionID, ClientID: client.ID, InstanceARN: instance.ARN, UserID: device.UserID, Created: now, RefreshExpires: now.Add(8 * time.Hour)}
	if !slices.Contains(client.GrantTypes, "refresh_token") {
		refresh = ""
	}
	out, e := s.issueToken(tx, session, refresh)
	if e != nil {
		return nil, e
	}
	device.State = "CONSUMED"
	if e = tx.PutDevice(device); e != nil {
		return nil, e
	}
	return out, nil
}
func (s *Service) currentUser(r Reader, instance Instance, userID string) error {
	if s.directory == nil {
		return errors.New("identity store is not configured")
	}
	_, e := s.directory.FindUser(r.Context(), directoryScope(instance), instance.StoreID, userID)
	return e
}
func (s *Service) refreshToken(tx Transaction, client Client, raw string) (*api.CreateTokenOutput, error) {
	old, e := tx.SessionByRefresh(tokenHash(raw))
	if e != nil || raw == "" || old.ClientID != client.ID || old.Revoked || !s.clock.Now().Before(old.RefreshExpires) {
		return nil, oauthError("InvalidGrantException", "invalid_grant", "The refresh token is invalid, expired, or revoked.", 400)
	}
	instance, e := tx.Instance(old.InstanceARN)
	if e != nil {
		return nil, oauthError("InvalidGrantException", "invalid_grant", "The instance is no longer available.", 400)
	}
	if e = s.currentUser(tx, instance, old.UserID); e != nil {
		return nil, oauthError("InvalidGrantException", "invalid_grant", "The directory user is no longer available.", 400)
	}
	id, e := randomToken()
	if e != nil {
		return nil, e
	}
	old.RefreshHash = ""
	if e = tx.PutSession(old); e != nil {
		return nil, e
	}
	next := old
	next.ID = id
	return s.issueToken(tx, next, raw)
}
func (s *Service) issueToken(tx Transaction, session Session, refresh string) (*api.CreateTokenOutput, error) {
	access, e := randomToken()
	if e != nil {
		return nil, e
	}
	session.AccessHash = tokenHash(access)
	session.AccessExpires = s.clock.Now().Add(time.Hour)
	if session.AccessExpires.After(session.RefreshExpires) {
		session.AccessExpires = session.RefreshExpires
	}
	if refresh != "" {
		session.RefreshHash = tokenHash(refresh)
	}
	if e = tx.PutSession(session); e != nil {
		return nil, e
	}
	out := &api.CreateTokenOutput{AccessToken: new(api.AccessToken(access)), ExpiresIn: new(api.ExpirationInSeconds(session.AccessExpires.Sub(s.clock.Now()) / time.Second)), TokenType: new(api.TokenType("Bearer"))}
	if refresh != "" {
		out.RefreshToken = new(api.RefreshToken(refresh))
	}
	return out, nil
}
func (s *Service) session(r Reader, raw string) (Session, Instance, *awswire.Error) {
	v, e := r.SessionByAccess(tokenHash(raw))
	if e != nil || raw == "" || v.Revoked || !s.clock.Now().Before(v.AccessExpires) {
		return Session{}, Instance{}, failure("UnauthorizedException", "The access token is invalid, expired, or revoked.", 401)
	}
	instance, e := r.Instance(v.InstanceARN)
	scope := scopeFor(r.Context())
	if e != nil || instance.Region != scope.Region || instance.Partition != scope.Partition {
		return Session{}, Instance{}, failure("UnauthorizedException", "The access token is not valid for this Region.", 401)
	}
	if e = s.currentUser(r, instance, v.UserID); e != nil {
		return Session{}, Instance{}, failure("UnauthorizedException", "The directory user is no longer available.", 401)
	}
	return v, instance, nil
}
