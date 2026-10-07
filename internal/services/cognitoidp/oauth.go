package cognitoidp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awsctx"
)

// OAuthKey names one hosted-federation transaction in a user pool. Token is
// the random part of the opaque handle returned as upstream state (authorize
// phase) or as the client's authorization code (code phase).
type OAuthKey struct {
	PoolKey
	Token string
}

// OAuthRecord is single-use hosted-federation state. The authorize phase keeps
// the client request and the upstream nonce/PKCE verifier until the identity
// provider calls back; the code phase binds an issued authorization code to the
// federated user, client, redirect URI, scope, nonce and PKCE challenge.
type OAuthRecord struct {
	Key              OAuthKey
	ClientID         string
	ProviderName     string
	RedirectURI      string
	ClientState      string
	Nonce            string
	PKCEChallenge    string
	UpstreamNonce    string
	UpstreamVerifier string
	Scope            string
	Username         string
	Phase            string
	Expires          time.Time
}

const (
	oauthPhaseAuthorize = "authorize"
	oauthPhaseCode      = "code"
	// A sign-in at the identity provider must complete within this window.
	oauthAuthorizeLifetime = 10 * time.Minute
	// Cognito authorization codes are valid for five minutes.
	oauthCodeLifetime = 5 * time.Minute
	oauthFormLimit    = 64 << 10
	oauthTokenLength  = 43
)

var (
	pkceValuePattern     = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	upstreamErrorPattern = regexp.MustCompile(`^[a-z_]{1,64}$`)
	hostedDomainPattern  = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.auth\.([a-z]{2}(?:-[a-z]+)+-[0-9]+)\.amazoncognito\.com$`)
)

// oauthError is an RFC 6749 error. Status applies only when the error is
// written directly instead of redirected to a validated client redirect URI.
type oauthError struct {
	Status            int
	Code, Description string
}

func (e *oauthError) Error() string { return e.Code + ": " + e.Description }

func oauthReject(code, description string) *oauthError {
	return &oauthError{Status: http.StatusBadRequest, Code: code, Description: description}
}

// ServeOAuth implements the hosted authorization-code federation endpoints for
// admitted social identity providers. The caller supplies trusted anonymous
// partition/Region metadata exactly as for public Cognito API calls; app client
// IDs, state handles and codes identify the owning pool.
func (s *Service) ServeOAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	switch r.URL.Path {
	case "/oauth2/authorize":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.oauthAuthorize(w, r)
	case "/oauth2/idpresponse":
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.oauthIdpResponse(w, r)
	case "/oauth2/token":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.oauthToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Service) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if repeatedParameter(q) {
		writeOAuthPage(w, oauthReject("invalid_request", "Request parameters must not repeat."))
		return
	}
	callback, err := s.oauthCallbackURL(r)
	if err != nil {
		writeOAuthPage(w, err)
		return
	}
	redirectURI := q.Get("redirect_uri")
	var redirectable bool
	var upstream string
	err = s.repository.Update(r.Context(), func(tx Transaction) error {
		redirectable, upstream = false, ""
		pool, client, err := s.oauthClient(tx, r.Host, q.Get("client_id"))
		if errors.Is(err, ErrNotFound) {
			return oauthReject("invalid_request", "client_id is invalid.")
		}
		if err != nil {
			return err
		}
		if redirectURI == "" || !slices.Contains(client.Data.CallbackURLs, api.RedirectUrlType(redirectURI)) {
			return oauthReject("invalid_request", "redirect_uri is not registered for the client.")
		}
		redirectable = true
		if !oauthFlowEnabled(client, "code") {
			return oauthReject("unauthorized_client", "The client is not allowed to use the authorization code grant.")
		}
		switch q.Get("response_type") {
		case "code":
		case "":
			return oauthReject("invalid_request", "response_type is required.")
		default:
			return oauthReject("unsupported_response_type", "Only the authorization code response type is implemented.")
		}
		scope, err := grantedScopes(client, q.Get("scope"))
		if err != nil {
			return err
		}
		provider, err := oauthProvider(tx, pool, client, q.Get("identity_provider"), q.Get("idp_identifier"))
		if err != nil {
			return err
		}
		challenge, method := q.Get("code_challenge"), q.Get("code_challenge_method")
		if (challenge != "" || method != "") && (method != "S256" || len(challenge) != oauthTokenLength || !pkceValuePattern.MatchString(challenge)) {
			return oauthReject("invalid_request", "PKCE requires an S256 code_challenge.")
		}
		if len(q.Get("state")) > 2048 || len(q.Get("nonce")) > 2048 {
			return oauthReject("invalid_request", "state and nonce must not exceed 2048 characters.")
		}
		rec := OAuthRecord{
			ClientID: client.Key.ID, ProviderName: provider.Key.Name, RedirectURI: redirectURI,
			ClientState: q.Get("state"), Nonce: q.Get("nonce"), PKCEChallenge: challenge, Scope: scope,
			Phase: oauthPhaseAuthorize, Expires: s.clock.Now().UTC().Add(oauthAuthorizeLifetime),
		}
		token, err := newOAuthToken()
		if err != nil {
			return err
		}
		rec.Key = OAuthKey{PoolKey: pool.Key, Token: token}
		if rec.UpstreamNonce, err = newOAuthToken(); err != nil {
			return err
		}
		if rec.UpstreamVerifier, err = newOAuthToken(); err != nil {
			return err
		}
		config, err := socialProviderConfig(provider)
		if err != nil {
			return err
		}
		if upstream, err = config.authorizeURL(provider, rec, callback); err != nil {
			return err
		}
		if err = tx.DeleteExpiredOAuth(pool.Key, s.clock.Now().UTC()); err != nil {
			return err
		}
		return tx.PutOAuth(rec)
	})
	if err != nil {
		if redirectable {
			redirectOAuthError(w, r, redirectURI, q.Get("state"), err)
			return
		}
		writeOAuthPage(w, err)
		return
	}
	http.Redirect(w, r, upstream, http.StatusFound)
}

// oauthIdpResponse consumes the authorize state before any upstream call, so a
// replayed or concurrent callback cannot exchange the same upstream code twice.
// The code exchange, inbound federation trigger and PreSignUp trigger run
// outside repository transactions; user mapping and code issuance revalidate the
// pool, client and provider in the final transaction.
func (s *Service) oauthIdpResponse(w http.ResponseWriter, r *http.Request) {
	params, err := oauthParameters(w, r)
	if err != nil {
		writeOAuthPage(w, err)
		return
	}
	ctx := r.Context()
	var pool PoolRecord
	var client ClientRecord
	var provider ProviderRecord
	var rec OAuthRecord
	var rejected error
	err = s.repository.Update(ctx, func(tx Transaction) error {
		rejected = nil
		var err error
		pool, rec, err = s.oauthByHandle(tx, params.Get("state"))
		if errors.Is(err, ErrNotFound) {
			rejected = oauthReject("invalid_request", "The authorization state is invalid, expired or already used.")
			return nil
		}
		if err != nil {
			return err
		}
		if err = tx.DeleteOAuth(rec.Key); err != nil {
			return err
		}
		if rec.Phase != oauthPhaseAuthorize {
			rejected = oauthReject("invalid_request", "The authorization state is invalid, expired or already used.")
			rec = OAuthRecord{}
			return nil
		}
		if !s.clock.Now().Before(rec.Expires) {
			rejected = oauthReject("invalid_request", "The authorization request has expired.")
			return nil
		}
		client, provider, err = s.oauthParticipants(tx, pool, rec)
		if err != nil {
			var oauth *oauthError
			if errors.As(err, &oauth) {
				// The redirect URI is no longer vouched for by a permitting client.
				rejected, rec.RedirectURI = err, ""
				return nil
			}
		}
		return err
	})
	if err != nil {
		writeOAuthPage(w, err)
		return
	}
	if rejected != nil {
		if rec.RedirectURI == "" {
			writeOAuthPage(w, rejected)
			return
		}
		redirectOAuthError(w, r, rec.RedirectURI, rec.ClientState, rejected)
		return
	}
	fail := func(err error) { redirectOAuthError(w, r, rec.RedirectURI, rec.ClientState, err) }
	if code := params.Get("error"); code != "" {
		if !upstreamErrorPattern.MatchString(code) {
			code = "server_error"
		}
		fail(oauthReject(code, "The identity provider did not authorize the sign-in."))
		return
	}
	callback, err := s.oauthCallbackURL(r)
	if err != nil {
		fail(err)
		return
	}
	identity, err := s.upstreamIdentity(ctx, provider, callback, params.Get("code"), rec, params.Get("user"))
	if err != nil {
		fail(err)
		return
	}
	username := canonicalUsername(pool, provider.Key.Name+"_"+identity.Subject)
	if len(username) > 128 {
		fail(oauthReject("invalid_request", "The identity provider subject is too long."))
		return
	}
	source, err := s.inboundFederation(ctx, pool, client, provider, username, identity)
	if err != nil {
		fail(err)
		return
	}
	attributes := federatedAttributes(pool, provider, source)
	var exists bool
	if err = s.repository.View(ctx, func(tx Reader) error {
		_, err := tx.User(UserKey{PoolKey: pool.Key, Username: username})
		exists = err == nil
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}); err != nil {
		fail(err)
		return
	}
	var signup *preSignUpResponse
	if !exists {
		response, err := s.invokePreSignUp(ctx, pool, "PreSignUp_ExternalProvider", client.Key.ID, username, attributeValues(attributes), nil, nil)
		if err != nil {
			fail(err)
			return
		}
		signup = &response
	}
	var code OAuthRecord
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Pool(pool.Key)
		if errors.Is(err, ErrNotFound) {
			return oauthReject("invalid_request", "The user pool no longer exists.")
		}
		if err != nil {
			return err
		}
		currentClient, currentProvider, err := s.oauthParticipants(tx, current, rec)
		if err != nil {
			return err
		}
		// HTTP and customer Lambda ran outside this transaction. Their approval
		// cannot authorize a provider, client or pool configuration changed while
		// those effects were in flight.
		if !reflect.DeepEqual(current.Data, pool.Data) || !reflect.DeepEqual(currentClient.Data, client.Data) || !reflect.DeepEqual(currentProvider.Data, provider.Data) {
			return oauthReject("invalid_request", "The federation configuration changed during authentication.")
		}
		provider = currentProvider
		user, err := s.putFederatedUser(tx, current, provider, username, identity.Subject, attributes, signup)
		if err != nil {
			return err
		}
		token, err := newOAuthToken()
		if err != nil {
			return err
		}
		code = OAuthRecord{
			Key: OAuthKey{PoolKey: current.Key, Token: token}, ClientID: rec.ClientID, ProviderName: rec.ProviderName,
			RedirectURI: rec.RedirectURI, ClientState: rec.ClientState, Nonce: rec.Nonce, PKCEChallenge: rec.PKCEChallenge,
			Scope: rec.Scope, Username: user.Key.Username, Phase: oauthPhaseCode, Expires: s.clock.Now().UTC().Add(oauthCodeLifetime),
		}
		if err = tx.DeleteExpiredOAuth(current.Key, s.clock.Now().UTC()); err != nil {
			return err
		}
		return tx.PutOAuth(code)
	})
	if err != nil {
		fail(err)
		return
	}
	values := url.Values{"code": {oauthHandle(code.Key)}}
	if rec.ClientState != "" {
		values.Set("state", rec.ClientState)
	}
	redirectWith(w, r, rec.RedirectURI, values)
}

// oauthParticipants revalidates that the client still permits code federation
// through the provider named by an OAuth transaction.
func (s *Service) oauthParticipants(r Reader, pool PoolRecord, rec OAuthRecord) (ClientRecord, ProviderRecord, error) {
	client, err := r.Client(ClientKey{PoolKey: pool.Key, ID: rec.ClientID})
	if errors.Is(err, ErrNotFound) {
		return ClientRecord{}, ProviderRecord{}, oauthReject("invalid_request", "The app client no longer exists.")
	}
	if err != nil {
		return ClientRecord{}, ProviderRecord{}, err
	}
	if !oauthFlowEnabled(client, "code") || !slices.Contains(client.Data.CallbackURLs, api.RedirectUrlType(rec.RedirectURI)) {
		return ClientRecord{}, ProviderRecord{}, oauthReject("unauthorized_client", "The client no longer permits this authorization code grant.")
	}
	provider, err := oauthProvider(r, pool, client, rec.ProviderName, "")
	return client, provider, err
}

func (s *Service) oauthToken(w http.ResponseWriter, r *http.Request) {
	params, err := oauthParameters(w, r)
	if err != nil {
		writeOAuthJSONError(w, err, false)
		return
	}
	clientID, secret, basic, err := oauthClientCredentials(r, params)
	if err != nil {
		writeOAuthJSONError(w, err, basic)
		return
	}
	var result *tokenGrant
	var rejected *oauthError
	err = s.repository.Update(r.Context(), func(tx Transaction) error {
		result, rejected = nil, nil
		var err error
		switch params.Get("grant_type") {
		case "authorization_code":
			result, rejected, err = s.redeemOAuthCode(tx, r.Host, clientID, secret, params)
		case "refresh_token":
			result, rejected, err = s.refreshOAuthToken(tx, r.Host, clientID, secret, params)
		case "":
			rejected = oauthReject("invalid_request", "grant_type is required.")
		default:
			rejected = oauthReject("unsupported_grant_type", "Only authorization_code and refresh_token grants are implemented.")
		}
		return err
	})
	if err == nil && rejected != nil {
		err = rejected
	}
	if err != nil {
		writeOAuthJSONError(w, err, basic)
		return
	}
	body := struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token,omitempty"`
		RefreshToken string `json:"refresh_token,omitempty"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}{AccessToken: value(result.AccessToken), IDToken: value(result.IdToken), RefreshToken: value(result.RefreshToken), TokenType: "Bearer"}
	if result.ExpiresIn != nil {
		body.ExpiresIn = int64(*result.ExpiresIn)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

type tokenGrant = api.AuthenticationResultType

// redeemOAuthCode deletes the code before validating the redemption; an
// invalid or replayed redemption commits that deletion and returns rejected.
func (s *Service) redeemOAuthCode(tx Transaction, host, clientID, secret string, params url.Values) (*tokenGrant, *oauthError, error) {
	invalidGrant := oauthReject("invalid_grant", "The authorization code is invalid, expired or already used.")
	pool, rec, err := s.oauthByHandle(tx, params.Get("code"))
	if errors.Is(err, ErrNotFound) {
		return nil, invalidGrant, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if err = tx.DeleteOAuth(rec.Key); err != nil {
		return nil, nil, err
	}
	if rec.Phase != oauthPhaseCode || !s.clock.Now().Before(rec.Expires) {
		return nil, invalidGrant, nil
	}
	if clientID == "" || clientID != rec.ClientID {
		return nil, invalidGrant, nil
	}
	if domainPool, ok, err := hostedDomainPool(tx, host); err != nil {
		return nil, nil, err
	} else if ok && domainPool != pool.Key {
		return nil, invalidGrant, nil
	}
	client, err := tx.Client(ClientKey{PoolKey: pool.Key, ID: rec.ClientID})
	if errors.Is(err, ErrNotFound) {
		return nil, &oauthError{Status: http.StatusUnauthorized, Code: "invalid_client", Description: "Client authentication failed."}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if rejected := authenticateOAuthClient(client, secret); rejected != nil {
		return nil, rejected, nil
	}
	if !oauthFlowEnabled(client, "code") {
		return nil, oauthReject("unauthorized_client", "The client is not allowed to use the authorization code grant."), nil
	}
	if params.Get("redirect_uri") != rec.RedirectURI {
		return nil, invalidGrant, nil
	}
	if rec.PKCEChallenge != "" {
		verifier := params.Get("code_verifier")
		if !pkceValuePattern.MatchString(verifier) || subtle.ConstantTimeCompare([]byte(pkceS256(verifier)), []byte(rec.PKCEChallenge)) != 1 {
			return nil, invalidGrant, nil
		}
	}
	user, err := tx.User(UserKey{PoolKey: pool.Key, Username: rec.Username})
	if errors.Is(err, ErrNotFound) {
		return nil, invalidGrant, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if userEnabled(user) != nil {
		return nil, oauthReject("invalid_grant", "User is disabled."), nil
	}
	result, err := s.startSession(tx, pool, client, user, rec.Scope, rec.Nonce)
	return result, nil, err
}

func (s *Service) refreshOAuthToken(tx Transaction, host, clientID, secret string, params url.Values) (*tokenGrant, *oauthError, error) {
	pool, client, err := s.oauthClient(tx, host, clientID)
	if errors.Is(err, ErrNotFound) {
		return nil, &oauthError{Status: http.StatusUnauthorized, Code: "invalid_client", Description: "Client authentication failed."}, nil
	}
	if err != nil {
		var oauth *oauthError
		if errors.As(err, &oauth) {
			return nil, oauth, nil
		}
		return nil, nil, err
	}
	if rejected := authenticateOAuthClient(client, secret); rejected != nil {
		return nil, rejected, nil
	}
	if client.Data.AllowedOAuthFlowsUserPoolClient == nil || !bool(*client.Data.AllowedOAuthFlowsUserPoolClient) {
		return nil, oauthReject("unauthorized_client", "The client is not enabled for OAuth."), nil
	}
	result, err := s.refreshTokens(tx, pool, client, params.Get("refresh_token"), nil)
	if err != nil {
		wire := wireError(err)
		switch wire.Code {
		case "NotAuthorizedException", "RefreshTokenReuseException", "InvalidParameterException":
			description := wire.Message
			if description == "" {
				description = "Invalid refresh token."
			}
			return nil, oauthReject("invalid_grant", description), nil
		}
		return nil, nil, err
	}
	return result, nil, nil
}

// oauthClient resolves a public client ID with the same Region rules as
// public Cognito APIs. A native hosted domain host additionally binds the
// request to that domain's pool. Hosted endpoints require a pool domain.
func (s *Service) oauthClient(r Reader, host, id string) (PoolRecord, ClientRecord, error) {
	if id == "" {
		return PoolRecord{}, ClientRecord{}, ErrNotFound
	}
	client, err := publicClient(r, id)
	if err != nil {
		return PoolRecord{}, ClientRecord{}, err
	}
	pool, err := r.Pool(client.Key.PoolKey)
	if err != nil {
		return PoolRecord{}, ClientRecord{}, err
	}
	if domainPool, ok, err := hostedDomainPool(r, host); err != nil {
		return PoolRecord{}, ClientRecord{}, err
	} else if ok && domainPool != pool.Key {
		return PoolRecord{}, ClientRecord{}, ErrNotFound
	}
	if value(pool.Data.Domain) == "" {
		return PoolRecord{}, ClientRecord{}, oauthReject("invalid_request", "The user pool has no domain; hosted OAuth endpoints require a user pool domain.")
	}
	return pool, client, nil
}

// hostedDomainPool resolves <prefix>.auth.<region>.amazoncognito.com. A host
// naming an absent domain cannot match any pool.
func hostedDomainPool(r Reader, host string) (PoolKey, bool, error) {
	prefix, region, ok := hostedDomain(host)
	if !ok {
		return PoolKey{}, false, nil
	}
	pool, err := r.PoolByDomain(awsctx.FromContext(r.Context()).Partition, region, prefix)
	if errors.Is(err, ErrNotFound) {
		return PoolKey{}, true, nil
	}
	return pool.Key, true, err
}

func hostedDomain(host string) (string, string, bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	m := hostedDomainPattern.FindStringSubmatch(strings.ToLower(host))
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// oauthCallbackURL is the provider redirect URI. Providers redirect back to the
// registered URI, so authorize and callback requests derive the same value.
func (s *Service) oauthCallbackURL(r *http.Request) (string, error) {
	if _, _, ok := hostedDomain(r.Host); ok {
		return "https://" + strings.ToLower(r.Host) + "/oauth2/idpresponse", nil
	}
	if s.publicEndpoint == "" {
		return "", &oauthError{Status: http.StatusInternalServerError, Code: "server_error", Description: "The Cognito public endpoint is not configured."}
	}
	return strings.TrimRight(s.publicEndpoint, "/") + "/oauth2/idpresponse", nil
}

func (s *Service) oauthByHandle(r Reader, handle string) (PoolRecord, OAuthRecord, error) {
	poolID, token, ok := strings.Cut(handle, ".")
	if !ok || poolID == "" || len(token) != oauthTokenLength {
		return PoolRecord{}, OAuthRecord{}, ErrNotFound
	}
	pool, err := r.PoolByID(awsctx.FromContext(r.Context()).Partition, publicPoolRegion(r.Context(), poolID), poolID)
	if err != nil {
		return PoolRecord{}, OAuthRecord{}, err
	}
	rec, err := r.OAuth(OAuthKey{PoolKey: pool.Key, Token: token})
	return pool, rec, err
}

func oauthHandle(key OAuthKey) string { return key.ID + "." + key.Token }

func newOAuthToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func oauthFlowEnabled(client ClientRecord, flow string) bool {
	return client.Data.AllowedOAuthFlowsUserPoolClient != nil && bool(*client.Data.AllowedOAuthFlowsUserPoolClient) && slices.Contains(client.Data.AllowedOAuthFlows, api.OAuthFlowType(flow))
}

// grantedScopes defaults to every allowed client scope, as Cognito does when
// scope is omitted.
func grantedScopes(client ClientRecord, requested string) (string, error) {
	var scopes []string
	if strings.TrimSpace(requested) == "" {
		for _, scope := range client.Data.AllowedOAuthScopes {
			scopes = append(scopes, string(scope))
		}
	} else {
		for _, scope := range strings.Fields(requested) {
			if !slices.Contains(client.Data.AllowedOAuthScopes, api.ScopeType(scope)) {
				return "", oauthReject("invalid_scope", "The requested scope is not allowed for the client: "+scope)
			}
			if !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
	}
	if len(scopes) == 0 {
		return "", oauthReject("invalid_scope", "The client allows no OAuth scopes.")
	}
	return strings.Join(scopes, " "), nil
}

// oauthProvider admits only a configured social provider enabled on the client.
// TODO: Comeback implement hosted native-user sign-in pages, implicit grants and
// userInfo; authorization-code federation does not implement those surfaces.
func oauthProvider(r Reader, pool PoolRecord, client ClientRecord, name, identifier string) (ProviderRecord, error) {
	if name == "" && identifier != "" {
		providers, err := r.Providers(pool.Key)
		if err != nil {
			return ProviderRecord{}, err
		}
		for _, p := range providers {
			if slices.Contains(p.Data.IdpIdentifiers, api.IdpIdentifierType(identifier)) {
				name = p.Key.Name
				break
			}
		}
		if name == "" {
			return ProviderRecord{}, oauthReject("invalid_request", "idp_identifier does not match an identity provider.")
		}
	}
	if name == "" || name == "COGNITO" {
		return ProviderRecord{}, oauthReject("invalid_request", "Hosted sign-in pages are not implemented; identity_provider must name a federated identity provider.")
	}
	if !slices.Contains(client.Data.SupportedIdentityProviders, api.ProviderNameType(name)) {
		return ProviderRecord{}, oauthReject("unauthorized_client", "The identity provider is not enabled for the client.")
	}
	provider, err := r.Provider(ProviderKey{PoolKey: pool.Key, Name: name})
	if errors.Is(err, ErrNotFound) {
		return ProviderRecord{}, oauthReject("invalid_request", "The identity provider does not exist.")
	}
	if err != nil {
		return ProviderRecord{}, err
	}
	if _, ok := socialProviderDetails[value(provider.Data.ProviderType)]; !ok {
		return ProviderRecord{}, oauthReject("invalid_request", "The identity provider type is not supported.")
	}
	return provider, nil
}

func authenticateOAuthClient(client ClientRecord, secret string) *oauthError {
	expected := value(client.Data.ClientSecret)
	if expected == "" {
		return nil
	}
	if secret == "" || subtle.ConstantTimeCompare([]byte(secret), []byte(expected)) != 1 {
		return &oauthError{Status: http.StatusUnauthorized, Code: "invalid_client", Description: "Client authentication failed."}
	}
	return nil
}

// oauthClientCredentials accepts HTTP Basic (RFC 6749 section 2.3.1 form
// encoded) or body credentials, never both.
func oauthClientCredentials(r *http.Request, params url.Values) (string, string, bool, error) {
	if r.Header.Get("Authorization") == "" {
		return params.Get("client_id"), params.Get("client_secret"), false, nil
	}
	user, password, ok := r.BasicAuth()
	if !ok {
		return "", "", true, &oauthError{Status: http.StatusUnauthorized, Code: "invalid_client", Description: "Client authentication failed."}
	}
	id, err := url.QueryUnescape(user)
	if err != nil {
		return "", "", true, &oauthError{Status: http.StatusUnauthorized, Code: "invalid_client", Description: "Client authentication failed."}
	}
	secret, err := url.QueryUnescape(password)
	if err != nil {
		return "", "", true, &oauthError{Status: http.StatusUnauthorized, Code: "invalid_client", Description: "Client authentication failed."}
	}
	if params.Has("client_secret") || (params.Get("client_id") != "" && params.Get("client_id") != id) {
		return "", "", true, oauthReject("invalid_request", "Use exactly one client authentication method.")
	}
	return id, secret, true, nil
}

// oauthParameters reads GET query parameters or a bounded form body; POST
// parameters never come from the URL query.
func oauthParameters(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	var params url.Values
	if r.Method == http.MethodGet {
		params = r.URL.Query()
	} else {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/x-www-form-urlencoded" {
			return nil, oauthReject("invalid_request", "The request body must be application/x-www-form-urlencoded.")
		}
		r.Body = http.MaxBytesReader(w, r.Body, oauthFormLimit)
		if err := r.ParseForm(); err != nil {
			return nil, oauthReject("invalid_request", "The request body is invalid.")
		}
		params = r.PostForm
	}
	if repeatedParameter(params) {
		return nil, oauthReject("invalid_request", "Request parameters must not repeat.")
	}
	return params, nil
}

func repeatedParameter(values url.Values) bool {
	for _, v := range values {
		if len(v) > 1 {
			return true
		}
	}
	return false
}

func redirectWith(w http.ResponseWriter, r *http.Request, base string, params url.Values) {
	target, err := url.Parse(base)
	if err != nil {
		writeOAuthPage(w, oauthReject("invalid_request", "redirect_uri is invalid."))
		return
	}
	q := target.Query()
	for k, v := range params {
		q[k] = v
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// redirectOAuthError reports failures after redirect_uri validation to the
// client. Trigger and service errors keep their Cognito message.
func redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state string, err error) {
	code, description := oauthErrorFields(err)
	values := url.Values{"error": {code}, "error_description": {description}}
	if state != "" {
		values.Set("state", state)
	}
	redirectWith(w, r, redirectURI, values)
}

func oauthErrorFields(err error) (string, string) {
	var oauth *oauthError
	if errors.As(err, &oauth) {
		return oauth.Code, oauth.Description
	}
	wire := wireError(err)
	if wire.Code == "InternalErrorException" {
		return "server_error", wire.Message
	}
	return "invalid_request", wire.Message
}

func writeOAuthPage(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var oauth *oauthError
	if errors.As(err, &oauth) {
		status = oauth.Status
	}
	code, description := oauthErrorFields(err)
	http.Error(w, code+": "+description, status)
}

func writeOAuthJSONError(w http.ResponseWriter, err error, basic bool) {
	status := http.StatusInternalServerError
	var oauth *oauthError
	if errors.As(err, &oauth) {
		status = oauth.Status
	}
	code, description := oauthErrorFields(err)
	if status == http.StatusUnauthorized && basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="cognito"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}
