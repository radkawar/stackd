package cognitoidp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/jwt"
)

// Social endpoints and issuers follow the provider's published OAuth/OIDC
// protocol. Describe-generated endpoint metadata is not configuration input.
type socialProvider struct {
	kind               string
	authorizeEndpoint  string
	tokenEndpoint      string
	attributesEndpoint string
	issuer             string
	extraIssuers       []string
	tokenMethod        string
	subjectClaim       string
	idToken, pkce      bool
}

var (
	facebookVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+$`)
	facebookFieldPattern   = regexp.MustCompile(`^[a-z_]+$`)
)

const upstreamResponseLimit = 1 << 20

func providerDetail(p ProviderRecord, key string) string {
	return strings.TrimSpace(string(p.Data.ProviderDetails[api.StringType(key)]))
}

func socialProviderConfig(p ProviderRecord) (socialProvider, error) {
	kind := value(p.Data.ProviderType)
	var c socialProvider
	switch kind {
	case "Google":
		c = socialProvider{authorizeEndpoint: "https://accounts.google.com/o/oauth2/v2/auth", tokenEndpoint: "https://oauth2.googleapis.com/token", attributesEndpoint: "https://openidconnect.googleapis.com/v1/userinfo", issuer: "https://accounts.google.com", extraIssuers: []string{"accounts.google.com"}, tokenMethod: http.MethodPost, subjectClaim: "sub", idToken: true, pkce: true}
	case "Facebook":
		version := providerDetail(p, "api_version")
		if version == "" {
			version = "v17.0"
		}
		if !facebookVersionPattern.MatchString(version) {
			return c, oauthReject("invalid_request", "The Facebook api_version is invalid.")
		}
		c = socialProvider{authorizeEndpoint: "https://www.facebook.com/" + version + "/dialog/oauth", tokenEndpoint: "https://graph.facebook.com/" + version + "/oauth/access_token", attributesEndpoint: "https://graph.facebook.com/" + version + "/me?fields=", tokenMethod: http.MethodGet, subjectClaim: "id", pkce: true}
	case "LoginWithAmazon":
		c = socialProvider{authorizeEndpoint: "https://www.amazon.com/ap/oa", tokenEndpoint: "https://api.amazon.com/auth/o2/token", attributesEndpoint: "https://api.amazon.com/user/profile", tokenMethod: http.MethodPost, subjectClaim: "user_id", pkce: true}
	case "SignInWithApple":
		c = socialProvider{authorizeEndpoint: "https://appleid.apple.com/auth/authorize", tokenEndpoint: "https://appleid.apple.com/auth/token", issuer: "https://appleid.apple.com", tokenMethod: http.MethodPost, subjectClaim: "sub", idToken: true}
	default:
		return c, oauthReject("invalid_request", "The identity provider type is not supported.")
	}
	c.kind = kind
	if claim := string(p.Data.AttributeMapping["username"]); claim != "" {
		c.subjectClaim = claim
	}
	for _, endpoint := range []string{c.authorizeEndpoint, c.tokenEndpoint, c.attributesEndpoint, c.issuer} {
		if endpoint == "" {
			continue
		}
		if err := upstreamURL(endpoint); err != nil {
			return c, err
		}
	}
	return c, nil
}

// Upstream endpoints receive client secrets and bearer tokens, so they must be
// absolute HTTPS URLs without embedded credentials or fragments.
func upstreamURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return &oauthError{Status: http.StatusBadGateway, Code: "server_error", Description: "The identity provider endpoint must be an absolute HTTPS URL."}
	}
	return nil
}

func upstreamFailure(description string) error {
	return &oauthError{Status: http.StatusBadGateway, Code: "server_error", Description: description}
}

func (c socialProvider) authorizeURL(p ProviderRecord, rec OAuthRecord, callback string) (string, error) {
	u, err := url.Parse(c.authorizeEndpoint)
	if err != nil {
		return "", upstreamFailure("The identity provider authorize URL is invalid.")
	}
	q := u.Query()
	q.Set("client_id", providerDetail(p, "client_id"))
	q.Set("redirect_uri", callback)
	q.Set("response_type", "code")
	q.Set("scope", providerDetail(p, "authorize_scopes"))
	q.Set("state", oauthHandle(rec.Key))
	if c.idToken {
		q.Set("nonce", rec.UpstreamNonce)
	}
	if c.pkce {
		q.Set("code_challenge", pkceS256(rec.UpstreamVerifier))
		q.Set("code_challenge_method", "S256")
	}
	if c.kind == "SignInWithApple" {
		// Apple requires form_post when name or email scopes are requested.
		q.Set("response_mode", "form_post")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// upstreamIdentity is the authenticated provider result. TokenResponse,
// IDToken and UserInfo are the InboundFederation request.attributes members.
type upstreamIdentity struct {
	Subject                          string
	TokenResponse, IDToken, UserInfo map[string]string
}

// attributes merges UserInfo then ID token claims; validated ID token claims win.
func (i upstreamIdentity) attributes() map[string]string {
	out := make(map[string]string, len(i.UserInfo)+len(i.IDToken))
	for k, v := range i.UserInfo {
		out[k] = v
	}
	for k, v := range i.IDToken {
		out[k] = v
	}
	return out
}

// upstreamIdentity exchanges the provider code with the configured client
// credentials, then authenticates the identity: Google and Apple through a
// signature-verified ID token bound to our client ID and nonce; Facebook and
// Login with Amazon through their profile APIs called with the access token
// obtained by that authenticated code exchange. No unsigned browser-supplied
// claim selects the subject.
func (s *Service) upstreamIdentity(ctx context.Context, provider ProviderRecord, callback, code string, rec OAuthRecord, appleUser string) (upstreamIdentity, error) {
	if code == "" {
		return upstreamIdentity{}, oauthReject("invalid_request", "The identity provider response has no authorization code.")
	}
	c, err := socialProviderConfig(provider)
	if err != nil {
		return upstreamIdentity{}, err
	}
	tokens, err := s.exchangeUpstreamCode(ctx, c, provider, callback, code, rec.UpstreamVerifier)
	if err != nil {
		return upstreamIdentity{}, err
	}
	identity := upstreamIdentity{TokenResponse: tokens, IDToken: map[string]string{}, UserInfo: map[string]string{}}
	if c.idToken {
		raw := tokens["id_token"]
		if raw == "" {
			return upstreamIdentity{}, upstreamFailure("The identity provider did not return an ID token.")
		}
		if identity.IDToken, err = s.verifyUpstreamIDToken(ctx, c, providerDetail(provider, "client_id"), rec.UpstreamNonce, raw); err != nil {
			return upstreamIdentity{}, err
		}
	}
	if c.attributesEndpoint != "" {
		info, err := s.upstreamUserInfo(ctx, c, provider, tokens["access_token"])
		switch {
		case err != nil && !c.idToken:
			return upstreamIdentity{}, err
		case err != nil:
			// The ID token remains authoritative; Cognito documents userInfo as
			// empty when the UserInfo call fails.
		case c.idToken && info["sub"] != identity.IDToken["sub"]:
			// OIDC Core 5.3.2: a UserInfo response for another subject is discarded.
			return upstreamIdentity{}, upstreamFailure("The identity provider UserInfo subject does not match the ID token.")
		default:
			identity.UserInfo = info
		}
	}
	identity.Subject = identity.attributes()[c.subjectClaim]
	if identity.Subject == "" {
		return upstreamIdentity{}, upstreamFailure("The identity provider response has no subject " + c.subjectClaim + ".")
	}
	if c.kind == "SignInWithApple" && appleUser != "" {
		// Apple posts the user's name only on first authorization, outside the
		// signed ID token. It supplies profile names only, never identity.
		var user struct {
			Name struct {
				FirstName string `json:"firstName"`
				LastName  string `json:"lastName"`
			} `json:"name"`
		}
		if json.Unmarshal([]byte(appleUser), &user) == nil {
			if user.Name.FirstName != "" {
				identity.UserInfo["firstName"] = user.Name.FirstName
			}
			if user.Name.LastName != "" {
				identity.UserInfo["lastName"] = user.Name.LastName
			}
			if name := strings.TrimSpace(user.Name.FirstName + " " + user.Name.LastName); name != "" {
				identity.UserInfo["name"] = name
			}
		}
	}
	return identity, nil
}

func (s *Service) exchangeUpstreamCode(ctx context.Context, c socialProvider, p ProviderRecord, callback, code, verifier string) (map[string]string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback}, "client_id": {providerDetail(p, "client_id")}}
	secret := providerDetail(p, "client_secret")
	if c.kind == "SignInWithApple" {
		var err error
		if secret, err = appleClientSecret(p, c.issuer, time.Now()); err != nil {
			return nil, err
		}
	}
	form.Set("client_secret", secret)
	if c.pkce {
		form.Set("code_verifier", verifier)
	}
	var req *http.Request
	var err error
	if c.tokenMethod == http.MethodGet {
		u, perr := url.Parse(c.tokenEndpoint)
		if perr != nil {
			return nil, upstreamFailure("The identity provider token URL is invalid.")
		}
		q := u.Query()
		for k, v := range form {
			q[k] = v
		}
		u.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, strings.NewReader(form.Encode()))
		if req != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return nil, upstreamFailure("The identity provider token URL is invalid.")
	}
	req.Header.Set("Accept", "application/json")
	body, status, err := s.upstreamDo(req)
	if err != nil {
		return nil, upstreamFailure("The identity provider token endpoint is unreachable.")
	}
	object, err := jwt.Object(body)
	if status != http.StatusOK || err != nil {
		description := "The identity provider rejected the authorization code."
		if code, ok := jwt.String(object, "error"); ok && upstreamErrorPattern.MatchString(code) {
			description += " (" + code + ")"
		}
		return nil, upstreamFailure(description)
	}
	tokens := stringClaims(object)
	if tokens["access_token"] == "" {
		return nil, upstreamFailure("The identity provider did not return an access token.")
	}
	return tokens, nil
}

func (s *Service) verifyUpstreamIDToken(ctx context.Context, c socialProvider, audience, nonce, raw string) (map[string]string, error) {
	invalid := func(message string) (map[string]string, error) {
		return nil, upstreamFailure("Invalid identity provider ID token: " + message)
	}
	token, err := jwt.Parse(raw, func(algorithm string) bool { return algorithm == "RS256" })
	if err != nil {
		return invalid("malformed or unsupported algorithm.")
	}
	keys, err := s.upstreamSigningKeys(ctx, c.issuer)
	if err != nil {
		return nil, err
	}
	key, ok := keys[token.KeyID]
	if token.KeyID == "" || !ok {
		return invalid("unknown signing key.")
	}
	if jwt.VerifyRSA(token, key) != nil {
		return invalid("signature verification failed.")
	}
	issuer, _ := jwt.String(token.Claims, "iss")
	if issuer != c.issuer && !slices.Contains(c.extraIssuers, issuer) {
		return invalid("issuer mismatch.")
	}
	var audiences []string
	if one, ok := jwt.String(token.Claims, "aud"); ok {
		audiences = []string{one}
	} else if json.Unmarshal(token.Claims["aud"], &audiences) != nil {
		return invalid("audience is malformed.")
	}
	if !slices.Contains(audiences, audience) {
		return invalid("audience mismatch.")
	}
	if len(audiences) > 1 {
		if azp, _ := jwt.String(token.Claims, "azp"); azp != audience {
			return invalid("authorized party mismatch.")
		}
	}
	now := s.clock.Now().Unix()
	expires, ok := numericClaim(token.Claims, "exp")
	if !ok || expires <= now {
		return invalid("expired.")
	}
	if issued, ok := numericClaim(token.Claims, "iat"); !ok || issued > now+300 {
		return invalid("issued in the future.")
	}
	got, _ := jwt.String(token.Claims, "nonce")
	if subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return invalid("nonce mismatch.")
	}
	if sub, _ := jwt.String(token.Claims, "sub"); sub == "" {
		return invalid("subject is missing.")
	}
	return stringClaims(token.Claims), nil
}

func numericClaim(claims map[string]json.RawMessage, name string) (int64, bool) {
	var v float64
	if raw, ok := claims[name]; !ok || json.Unmarshal(raw, &v) != nil {
		return 0, false
	}
	return int64(v), true
}

// upstreamSigningKeys trusts only keys from the configured issuer's OIDC
// discovery document; JOSE headers never introduce keys.
func (s *Service) upstreamSigningKeys(ctx context.Context, issuer string) (map[string]*rsa.PublicKey, error) {
	fetch := func(endpoint string) (map[string]json.RawMessage, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		body, status, err := s.upstreamDo(req)
		if err != nil || status != http.StatusOK {
			return nil, errors.New("unavailable")
		}
		return jwt.Object(body)
	}
	unavailable := upstreamFailure("The identity provider signing keys are unavailable.")
	document, err := fetch(strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration")
	if err != nil {
		return nil, unavailable
	}
	discovered, _ := jwt.String(document, "issuer")
	jwksURI, _ := jwt.String(document, "jwks_uri")
	if discovered != issuer || upstreamURL(jwksURI) != nil {
		return nil, unavailable
	}
	set, err := fetch(jwksURI)
	if err != nil {
		return nil, unavailable
	}
	var entries []struct {
		ID        string `json:"kid"`
		Type      string `json:"kty"`
		Use       string `json:"use"`
		Algorithm string `json:"alg"`
		N         string `json:"n"`
		E         string `json:"e"`
	}
	if json.Unmarshal(set["keys"], &entries) != nil {
		return nil, unavailable
	}
	keys := map[string]*rsa.PublicKey{}
	for _, entry := range entries {
		if entry.ID == "" || entry.Type != "RSA" || (entry.Use != "" && entry.Use != "sig") || (entry.Algorithm != "" && entry.Algorithm != "RS256") {
			continue
		}
		if key, err := jwt.RSAKey(entry.N, entry.E); err == nil && key.N.BitLen() >= 2048 {
			keys[entry.ID] = key
		}
	}
	if len(keys) == 0 {
		return nil, unavailable
	}
	return keys, nil
}

func (s *Service) upstreamUserInfo(ctx context.Context, c socialProvider, p ProviderRecord, accessToken string) (map[string]string, error) {
	if accessToken == "" {
		return nil, upstreamFailure("The identity provider did not return an access token.")
	}
	u, err := url.Parse(c.attributesEndpoint)
	if err != nil {
		return nil, upstreamFailure("The identity provider attributes URL is invalid.")
	}
	if c.kind == "Facebook" {
		q := u.Query()
		if q.Has("fields") && q.Get("fields") == "" {
			q.Set("fields", strings.Join(facebookFields(p), ","))
		}
		// Graph API appsecret_proof binds the call to this app's secret.
		mac := hmac.New(sha256.New, []byte(providerDetail(p, "client_secret")))
		mac.Write([]byte(accessToken))
		q.Set("appsecret_proof", hex.EncodeToString(mac.Sum(nil)))
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, upstreamFailure("The identity provider attributes URL is invalid.")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	body, status, err := s.upstreamDo(req)
	if err != nil || status != http.StatusOK {
		return nil, upstreamFailure("The identity provider user attributes are unavailable.")
	}
	object, err := jwt.Object(body)
	if err != nil {
		return nil, upstreamFailure("The identity provider user attributes are invalid.")
	}
	return stringClaims(object), nil
}

// facebookFields requests the subject and every mapped Graph field.
func facebookFields(p ProviderRecord) []string {
	fields := []string{"id"}
	for _, claim := range p.Data.AttributeMapping {
		name := string(claim)
		if facebookFieldPattern.MatchString(name) && !slices.Contains(fields, name) {
			fields = append(fields, name)
		}
	}
	slices.Sort(fields[1:])
	return fields
}

// upstreamDo never follows redirects, so client secrets and bearer tokens are
// only sent to the configured endpoint. It runs outside repository transactions.
func (s *Service) upstreamDo(req *http.Request) ([]byte, int, error) {
	client := *s.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, upstreamResponseLimit+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > upstreamResponseLimit {
		return nil, 0, errors.New("identity provider response is too large")
	}
	return body, resp.StatusCode, nil
}

// stringClaims renders provider JSON as Cognito's string attribute map:
// strings verbatim, other JSON values in compact JSON form.
func stringClaims(object map[string]json.RawMessage) map[string]string {
	out := make(map[string]string, len(object))
	for k, raw := range object {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			out[k] = text
			continue
		}
		var compact bytes.Buffer
		if json.Compact(&compact, raw) == nil && compact.String() != "null" {
			out[k] = compact.String()
		}
	}
	return out
}

// appleClientSecret is Apple's ES256 client-secret JWT. Apple validates it
// against wall time, so it does not use the service clock.
func appleClientSecret(p ProviderRecord, audience string, now time.Time) (string, error) {
	invalid := upstreamFailure("The Sign in with Apple private_key is not a PKCS #8 P-256 key.")
	material := []byte(providerDetail(p, "private_key"))
	var der []byte
	if block, _ := pem.Decode(material); block != nil {
		der = block.Bytes
	} else {
		decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(material)), ""))
		if err != nil {
			return "", invalid
		}
		der = decoded
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return "", invalid
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return "", invalid
	}
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": providerDetail(p, "key_id")})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{"iss": providerDetail(p, "team_id"), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "aud": audience, "sub": providerDetail(p, "client_id")})
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	r, sv, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	sv.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
