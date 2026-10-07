package cognitoidp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const (
	oauthTestCallback    = "https://app.example.com/callback"
	oauthTestIdpResponse = "http://localhost:4566/oauth2/idpresponse"
	oauthTestSubject     = "1234567890"
)

// fakeGoogle is an HTTPS OpenID provider with discovery, JWKS, token and
// UserInfo endpoints. The authorize endpoint is never fetched: the test acts
// as the browser and copies state/nonce/PKCE from the redirect.
type fakeGoogle struct {
	server           *httptest.Server
	key, signer      *rsa.PrivateKey
	clientID, secret string
	nonce, challenge string
	issuedNonce      string
	tokenCalls       int
	userInfoSubject  string
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGoogle{key: key, signer: key, clientID: "google-client", secret: "google-secret", userInfoSubject: oauthTestSubject}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeGoogle) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://accounts.google.com", "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"})
	case "/keys":
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
		}}})
	case "/token":
		f.tokenCalls++
		if r.Method != http.MethodPost || r.ParseForm() != nil || r.PostForm.Get("client_id") != f.clientID || r.PostForm.Get("client_secret") != f.secret ||
			r.PostForm.Get("code") != "upstream-code" || r.PostForm.Get("redirect_uri") != oauthTestIdpResponse || pkceS256(r.PostForm.Get("code_verifier")) != f.challenge {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		nonce := f.nonce
		if f.issuedNonce != "" {
			nonce = f.issuedNonce
		}
		now := time.Now()
		id := signRS256(f.signer, "k1", map[string]any{
			"iss": "https://accounts.google.com", "aud": f.clientID, "sub": oauthTestSubject, "email": "ada@example.com",
			"email_verified": true, "nonce": nonce, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "upstream-access", "token_type": "Bearer", "expires_in": 3600, "id_token": id})
	case "/userinfo":
		if r.Header.Get("Authorization") != "Bearer upstream-access" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": f.userInfoSubject, "given_name": "Ada", "family_name": "Lovelace"})
	default:
		http.NotFound(w, r)
	}
}

func signRS256(key *rsa.PrivateKey, kid string, claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// federationInvoker stands in for the native Lambda invoker and records every
// trigger event; the InboundFederation response replaces given_name.
type federationInvoker struct{ events []map[string]any }

func (i *federationInvoker) InvokeTrigger(_ context.Context, _ PoolKey, _ string, payload []byte) ([]byte, error) {
	var event map[string]any
	if err := json.Unmarshal(payload, &event); err != nil {
		return nil, err
	}
	i.events = append(i.events, event)
	if event["triggerSource"] == "InboundFederation_ExternalProvider" {
		event["response"] = map[string]any{"userAttributesToMap": map[string]string{"email": "ada@example.com", "email_verified": "true", "given_name": "Grace"}}
	}
	return json.Marshal(event)
}

type oauthFixture struct {
	s                *Service
	google           *fakeGoogle
	invoker          *federationInvoker
	admin, public    context.Context
	poolID           string
	clientID, secret string
}

func newOAuthFixture(t *testing.T) *oauthFixture {
	t.Helper()
	fx := &oauthFixture{google: newFakeGoogle(t), invoker: &federationInvoker{}}
	fx.s = New(Config{Repository: NewMemoryRepository(nil), HTTPClient: fx.google.client(), PublicEndpoint: "http://localhost:4566", TriggerInvoker: fx.invoker})
	fx.admin = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})
	fx.public = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", Region: "us-east-1"})
	pool := fx.call(t, "CreateUserPool", &api.CreateUserPoolInput{
		PoolName: str[api.UserPoolNameType]("federated"), UsernameAttributes: api.UsernameAttributesListType{"email"},
		UserPoolTier: str[api.UserPoolTierType]("ESSENTIALS"),
		LambdaConfig: &api.LambdaConfigType{InboundFederation: &api.InboundFederationLambdaType{
			LambdaArn: str[api.ArnType]("arn:aws:lambda:us-east-1:123456789012:function:federation"), LambdaVersion: str[api.InboundFederationLambdaVersionType]("V1_0"),
		}},
	}).(*api.CreateUserPoolOutput).UserPool
	fx.poolID = value(pool.Id)
	fx.call(t, "CreateUserPoolDomain", &api.CreateUserPoolDomainInput{UserPoolId: pool.Id, Domain: str[api.DomainType]("guard-local")})
	g := fx.google
	fx.call(t, "CreateIdentityProvider", &api.CreateIdentityProviderInput{
		UserPoolId: pool.Id, ProviderName: str[api.ProviderNameTypeV2]("Google"), ProviderType: str[api.IdentityProviderTypeType]("Google"),
		ProviderDetails: api.ProviderDetailsType{
			"client_id": api.StringType(g.clientID), "client_secret": api.StringType(g.secret), "authorize_scopes": "openid email profile",
		},
		AttributeMapping: api.AttributeMappingType{"email": "email", "email_verified": "email_verified", "given_name": "given_name"},
	})
	client := fx.call(t, "CreateUserPoolClient", &api.CreateUserPoolClientInput{
		UserPoolId: pool.Id, ClientName: str[api.ClientNameType]("web"), GenerateSecret: ptr(api.GenerateSecret(true)),
		AllowedOAuthFlowsUserPoolClient: ptr(api.BooleanType(true)), AllowedOAuthFlows: api.OAuthFlowsType{"code"},
		AllowedOAuthScopes: api.ScopeListType{"openid", "email", "aws.cognito.signin.user.admin"},
		CallbackURLs:       api.CallbackURLsListType{oauthTestCallback}, SupportedIdentityProviders: api.SupportedIdentityProvidersListType{"Google"},
	}).(*api.CreateUserPoolClientOutput).UserPoolClient
	fx.clientID, fx.secret = value(client.ClientId), value(client.ClientSecret)
	return fx
}

func (fx *oauthFixture) call(t *testing.T, action string, in any) any {
	t.Helper()
	model, _ := awscatalog.LookupService("cognitoidp")
	op, _ := model.Operation(action)
	out, e := fx.s.ExecuteCommand(fx.admin, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: in})
	if e != nil {
		t.Fatalf("%s: %v", action, e)
	}
	return out
}

func (fx *oauthFixture) callError(action string, in any) *awswire.Error {
	model, _ := awscatalog.LookupService("cognitoidp")
	op, _ := model.Operation(action)
	_, e := fx.s.ExecuteCommand(fx.admin, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: in})
	return e
}

func (fx *oauthFixture) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	fx.s.ServeOAuth(w, r.WithContext(fx.public))
	return w
}

// authorize returns the upstream redirect query after the browser leg.
func (fx *oauthFixture) authorize(t *testing.T, extra url.Values) url.Values {
	t.Helper()
	q := url.Values{"client_id": {fx.clientID}, "response_type": {"code"}, "redirect_uri": {oauthTestCallback}, "identity_provider": {"Google"}, "state": {"client-state"}, "nonce": {"client-nonce"}, "scope": {"openid email aws.cognito.signin.user.admin"}}
	for k, v := range extra {
		q[k] = v
	}
	w := fx.serve(httptest.NewRequest(http.MethodGet, "http://localhost:4566/oauth2/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", w.Code, w.Body.String())
	}
	target, err := url.Parse(w.Header().Get("Location"))
	if err != nil || target.Scheme != "https" || target.Host != "accounts.google.com" || target.Path != "/o/oauth2/v2/auth" {
		t.Fatalf("authorize redirect=%q", w.Header().Get("Location"))
	}
	upstream := target.Query()
	if upstream.Get("redirect_uri") != oauthTestIdpResponse || upstream.Get("client_id") != fx.google.clientID || upstream.Get("code_challenge_method") != "S256" || upstream.Get("nonce") == "" {
		t.Fatalf("upstream authorize parameters=%v", upstream)
	}
	fx.google.nonce, fx.google.challenge = upstream.Get("nonce"), upstream.Get("code_challenge")
	return upstream
}

func (fx *oauthFixture) callback(state string) *httptest.ResponseRecorder {
	return fx.serve(httptest.NewRequest(http.MethodGet, "http://localhost:4566/oauth2/idpresponse?"+url.Values{"code": {"upstream-code"}, "state": {state}}.Encode(), nil))
}

func (fx *oauthFixture) token(form url.Values, basicID, basicSecret string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://localhost:4566/oauth2/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		r.SetBasicAuth(url.QueryEscape(basicID), url.QueryEscape(basicSecret))
	}
	return fx.serve(r)
}

func clientRedirect(t *testing.T, w *httptest.ResponseRecorder) url.Values {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	target, err := url.Parse(w.Header().Get("Location"))
	if err != nil || target.Scheme+"://"+target.Host+target.Path != oauthTestCallback {
		t.Fatalf("client redirect=%q", w.Header().Get("Location"))
	}
	return target.Query()
}

func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q", token)
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestHostedGoogleFederationRunsInboundTriggerAndIssuesSingleUseCode(t *testing.T) {
	fx := newOAuthFixture(t)
	verifier := strings.Repeat("v", 43)
	upstream := fx.authorize(t, url.Values{"code_challenge": {pkceS256(verifier)}, "code_challenge_method": {"S256"}})
	back := clientRedirect(t, fx.callback(upstream.Get("state")))
	if back.Get("state") != "client-state" || back.Get("code") == "" || back.Get("error") != "" {
		t.Fatalf("callback redirect=%v", back)
	}
	if len(fx.invoker.events) != 1 {
		t.Fatalf("trigger events=%d", len(fx.invoker.events))
	}
	event := fx.invoker.events[0]
	request := event["request"].(map[string]any)
	attributes := request["attributes"].(map[string]any)
	if event["userName"] != "Google_"+oauthTestSubject || request["providerType"] != "Google" ||
		attributes["idToken"].(map[string]any)["sub"] != oauthTestSubject || attributes["userInfo"].(map[string]any)["given_name"] != "Ada" ||
		attributes["tokenResponse"].(map[string]any)["access_token"] != "upstream-access" {
		t.Fatalf("inbound federation event=%v", event)
	}
	user := fx.call(t, "AdminGetUser", &api.AdminGetUserInput{UserPoolId: str[api.UserPoolIdType](fx.poolID), Username: str[api.UsernameType]("Google_" + oauthTestSubject)}).(*api.AdminGetUserOutput)
	got := map[string]string{}
	for _, a := range user.UserAttributes {
		got[value(a.Name)] = value(a.Value)
	}
	if value(user.UserStatus) != "EXTERNAL_PROVIDER" || got["given_name"] != "Grace" || got["email"] != "ada@example.com" || got["email_verified"] != "true" || !strings.Contains(got["identities"], `"userId":"`+oauthTestSubject+`"`) {
		t.Fatalf("federated user status=%s attributes=%v", value(user.UserStatus), got)
	}

	redeem := url.Values{"grant_type": {"authorization_code"}, "code": {back.Get("code")}, "redirect_uri": {oauthTestCallback}, "code_verifier": {verifier}}
	w := fx.token(redeem, fx.clientID, fx.secret)
	if w.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", w.Code, w.Body.String())
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tokens); err != nil || tokens.AccessToken == "" || tokens.IDToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("token body=%s", w.Body.String())
	}
	id := jwtClaims(t, tokens.IDToken)
	sum := sha256.Sum256([]byte(tokens.AccessToken))
	if id["nonce"] != "client-nonce" || id["given_name"] != "Grace" || id["at_hash"] != base64.RawURLEncoding.EncodeToString(sum[:16]) || id["cognito:username"] != "Google_"+oauthTestSubject {
		t.Fatalf("id token claims=%v", id)
	}
	if identities, ok := id["identities"].([]any); !ok || len(identities) != 1 {
		t.Fatalf("identities claim=%v", id["identities"])
	}
	if scope := jwtClaims(t, tokens.AccessToken)["scope"]; scope != "openid email aws.cognito.signin.user.admin" {
		t.Fatalf("access scope=%v", scope)
	}
	// The issued access token is a real pool session token.
	if e := fx.callError("GetUser", &api.GetUserInput{AccessToken: str[api.TokenModelType](tokens.AccessToken)}); e != nil {
		t.Fatalf("GetUser with federated access token: %v", e)
	}

	if replay := fx.token(redeem, fx.clientID, fx.secret); replay.Code != http.StatusBadRequest || !strings.Contains(replay.Body.String(), "invalid_grant") {
		t.Fatalf("code replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	if replay := fx.callback(upstream.Get("state")); replay.Code != http.StatusBadRequest || fx.google.tokenCalls != 1 {
		t.Fatalf("state replay status=%d upstream token calls=%d", replay.Code, fx.google.tokenCalls)
	}
	refresh := fx.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}}, fx.clientID, fx.secret)
	if refresh.Code != http.StatusOK || !strings.Contains(refresh.Body.String(), "access_token") {
		t.Fatalf("refresh status=%d body=%s", refresh.Code, refresh.Body.String())
	}
}

func TestHostedFederationRejectsUnverifiedUpstreamIdentity(t *testing.T) {
	forged, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, tamper := range map[string]func(*fakeGoogle){
		"signature":        func(g *fakeGoogle) { g.signer = forged },
		"nonce":            func(g *fakeGoogle) { g.issuedNonce = "attacker-nonce" },
		"userinfo subject": func(g *fakeGoogle) { g.userInfoSubject = "someone-else" },
	} {
		t.Run(name, func(t *testing.T) {
			fx := newOAuthFixture(t)
			upstream := fx.authorize(t, nil)
			tamper(fx.google)
			back := clientRedirect(t, fx.callback(upstream.Get("state")))
			if back.Get("code") != "" || back.Get("error") == "" || back.Get("state") != "client-state" {
				t.Fatalf("callback redirect=%v", back)
			}
			if len(fx.invoker.events) != 0 {
				t.Fatalf("trigger ran for an unverified identity: %v", fx.invoker.events)
			}
			if e := fx.callError("AdminGetUser", &api.AdminGetUserInput{UserPoolId: str[api.UserPoolIdType](fx.poolID), Username: str[api.UsernameType]("Google_" + oauthTestSubject)}); e == nil || e.Code != "UserNotFoundException" {
				t.Fatalf("unverified identity created a user: %v", e)
			}
		})
	}
}

func TestHostedFederationTokenRedemptionBindings(t *testing.T) {
	fx := newOAuthFixture(t)
	other := fx.call(t, "CreateUserPoolClient", &api.CreateUserPoolClientInput{
		UserPoolId: str[api.UserPoolIdType](fx.poolID), ClientName: str[api.ClientNameType]("other"), GenerateSecret: ptr(api.GenerateSecret(true)),
		AllowedOAuthFlowsUserPoolClient: ptr(api.BooleanType(true)), AllowedOAuthFlows: api.OAuthFlowsType{"code"},
		AllowedOAuthScopes: api.ScopeListType{"openid"}, CallbackURLs: api.CallbackURLsListType{oauthTestCallback}, SupportedIdentityProviders: api.SupportedIdentityProvidersListType{"Google"},
	}).(*api.CreateUserPoolClientOutput).UserPoolClient
	verifier := strings.Repeat("a", 43)
	issue := func() string {
		upstream := fx.authorize(t, url.Values{"code_challenge": {pkceS256(verifier)}, "code_challenge_method": {"S256"}})
		return clientRedirect(t, fx.callback(upstream.Get("state"))).Get("code")
	}
	form := func(code, v string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {oauthTestCallback}, "code_verifier": {v}}
	}

	code := issue()
	if w := fx.token(form(code, verifier), fx.clientID, "wrong-secret"); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "invalid_client") {
		t.Fatalf("wrong secret status=%d body=%s", w.Code, w.Body.String())
	}
	if w := fx.token(form(code, verifier), fx.clientID, fx.secret); w.Code != http.StatusBadRequest {
		t.Fatalf("a rejected redemption must consume the code: status=%d", w.Code)
	}

	code = issue()
	if w := fx.token(form(code, strings.Repeat("b", 43)), fx.clientID, fx.secret); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_grant") {
		t.Fatalf("PKCE mismatch status=%d body=%s", w.Code, w.Body.String())
	}

	code = issue()
	if w := fx.token(form(code, verifier), value(other.ClientId), value(other.ClientSecret)); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_grant") {
		t.Fatalf("cross-client redemption status=%d body=%s", w.Code, w.Body.String())
	}

	code = issue()
	wrongRedirect := form(code, verifier)
	wrongRedirect.Set("redirect_uri", "https://app.example.com/other")
	if w := fx.token(wrongRedirect, fx.clientID, fx.secret); w.Code != http.StatusBadRequest {
		t.Fatalf("redirect mismatch status=%d", w.Code)
	}
}

func TestHostedFederationAuthorizeRestrictions(t *testing.T) {
	fx := newOAuthFixture(t)
	request := func(q url.Values) *httptest.ResponseRecorder {
		return fx.serve(httptest.NewRequest(http.MethodGet, "http://localhost:4566/oauth2/authorize?"+q.Encode(), nil))
	}
	base := func() url.Values {
		return url.Values{"client_id": {fx.clientID}, "response_type": {"code"}, "redirect_uri": {oauthTestCallback}, "identity_provider": {"Google"}, "state": {"s"}}
	}

	q := base()
	q.Set("redirect_uri", "https://attacker.example.com/callback")
	if w := request(q); w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Fatalf("unregistered redirect status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	q = base()
	q.Set("client_id", "unknownclient")
	if w := request(q); w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Fatalf("unknown client status=%d", w.Code)
	}
	q = base()
	q.Set("identity_provider", "Facebook")
	if got := clientRedirect(t, request(q)); got.Get("error") != "unauthorized_client" || got.Get("state") != "s" {
		t.Fatalf("disabled provider redirect=%v", got)
	}
	q = base()
	q.Set("scope", "phone")
	if got := clientRedirect(t, request(q)); got.Get("error") != "invalid_scope" {
		t.Fatalf("disallowed scope redirect=%v", got)
	}
	q = base()
	q.Set("code_challenge", strings.Repeat("c", 43))
	q.Set("code_challenge_method", "plain")
	if got := clientRedirect(t, request(q)); got.Get("error") != "invalid_request" {
		t.Fatalf("plain PKCE redirect=%v", got)
	}
	q = base()
	q.Set("response_type", "token")
	if got := clientRedirect(t, request(q)); got.Get("error") != "unsupported_response_type" {
		t.Fatalf("implicit grant redirect=%v", got)
	}
	// A pool in another Region does not resolve this client.
	fx.public = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", Region: "us-west-2"})
	if w := request(base()); w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Fatalf("cross-Region client status=%d", w.Code)
	}
}

func TestHostedFederationExpiredStateIsRejectedAndConsumed(t *testing.T) {
	fx := newOAuthFixture(t)
	upstream := fx.authorize(t, nil)
	poolID, token, _ := strings.Cut(upstream.Get("state"), ".")
	key := OAuthKey{PoolKey: PoolKey{Scope: Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: poolID}, Token: token}
	if err := fx.s.repository.Update(t.Context(), func(tx Transaction) error {
		rec, err := tx.OAuth(key)
		if err != nil {
			return err
		}
		rec.Expires = time.Now().Add(-time.Second)
		return tx.PutOAuth(rec)
	}); err != nil {
		t.Fatal(err)
	}
	if got := clientRedirect(t, fx.callback(upstream.Get("state"))); got.Get("error") != "invalid_request" || got.Get("code") != "" {
		t.Fatalf("expired state redirect=%v", got)
	}
	if fx.google.tokenCalls != 0 {
		t.Fatal("expired state reached the identity provider")
	}
	if err := fx.s.repository.View(t.Context(), func(r Reader) error {
		if _, err := r.OAuth(key); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired state retained: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type oauthFixtureTransport func(*http.Request) (*http.Response, error)

func (f oauthFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Operator-owned transport redirects only known canonical Google destinations
// to a trusted TLS fixture. ProviderDetails remains native credentials/scopes.
func (f *fakeGoogle) client() *http.Client {
	paths := map[string]string{
		"accounts.google.com/.well-known/openid-configuration": "/.well-known/openid-configuration",
		"oauth2.googleapis.com/token":                          "/token",
		"openidconnect.googleapis.com/v1/userinfo":             "/userinfo",
		"www.googleapis.com/oauth2/v3/certs":                   "/keys",
	}
	target, _ := url.Parse(f.server.URL)
	return &http.Client{Transport: oauthFixtureTransport(func(r *http.Request) (*http.Response, error) {
		path, ok := paths[r.URL.Host+r.URL.Path]
		if r.URL.Scheme != "https" || !ok {
			return nil, fmt.Errorf("unexpected upstream destination: %s", r.URL)
		}
		forwarded := r.Clone(r.Context())
		u := *r.URL
		u.Scheme, u.Host, u.Path = target.Scheme, target.Host, path
		forwarded.URL, forwarded.Host = &u, target.Host
		return f.server.Client().Transport.RoundTrip(forwarded)
	})}
}

func TestSocialProviderRejectsEndpointMetadataInputs(t *testing.T) {
	for _, key := range []string{"authorize_url", "token_url", "attributes_url", "oidc_issuer", "token_request_method", "attributes_url_add_attributes"} {
		t.Run(key, func(t *testing.T) {
			fx := newOAuthFixture(t)
			err := fx.callError("UpdateIdentityProvider", &api.UpdateIdentityProviderInput{
				UserPoolId: str[api.UserPoolIdType](fx.poolID), ProviderName: str[api.ProviderNameType]("Google"),
				ProviderDetails: api.ProviderDetailsType{api.StringType(key): "https://attacker.example.invalid"},
			})
			if err == nil || err.Code != "InvalidParameterException" {
				t.Fatalf("non-native endpoint metadata admitted: %v", err)
			}
		})
	}
	config, err := socialProviderConfig(ProviderRecord{Data: api.IdentityProviderType{
		ProviderType:    str[api.IdentityProviderTypeType]("Google"),
		ProviderDetails: api.ProviderDetailsType{"oidc_issuer": "https://attacker.example.invalid", "token_url": "https://attacker.example.invalid/token"},
	}})
	if err != nil || config.issuer != "https://accounts.google.com" || config.tokenEndpoint != "https://oauth2.googleapis.com/token" {
		t.Fatalf("stored metadata changed canonical authority: %+v %v", config, err)
	}
}
