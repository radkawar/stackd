package identitycenter

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/ssooidc"
	"stackd/internal/awsctx"
)

// AuthorizePath is the browser endpoint, not a modeled AWS JSON operation.
const AuthorizePath = "/authorize"

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.User != nil || strings.Contains(raw, "#") || u.Opaque != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Hostname() != ""
	case "http":
		ip := net.ParseIP(u.Hostname())
		return u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	default:
		// RFC 8252 private-use schemes use a reversed domain to avoid collisions.
		return strings.Contains(u.Scheme, ".") && u.Path != ""
	}
}

func registeredRedirect(registered []string, raw string) bool {
	if slices.Contains(registered, raw) {
		return true
	}
	if !validRedirectURI(raw) {
		return false
	}
	actual, _ := url.Parse(raw)
	ip := net.ParseIP(actual.Hostname())
	if actual.Scheme != "http" || ip == nil || !ip.IsLoopback() {
		return false
	}
	for _, allowed := range registered {
		u, err := url.Parse(allowed)
		if err != nil || u.Scheme != actual.Scheme || u.Hostname() != actual.Hostname() {
			continue
		}
		// RFC 8252 section 7.3 permits a dynamically allocated loopback port.
		candidate := *actual
		candidate.Host = u.Host
		if candidate.String() == allowed {
			return true
		}
	}
	return false
}

func (s *Service) issuerInstance(r Reader, partition, region, raw string) (Instance, error) {
	u, err := url.Parse(raw)
	if err == nil && u.Scheme == "https" && u.Host == issuerHost(partition) && u.User == nil && u.RawQuery == "" && u.Fragment == "" && strings.HasPrefix(u.Path, "/ssoins-") {
		v, err := r.Instance("arn:" + partition + ":sso:::instance" + u.Path)
		if err == nil && v.Partition == partition && v.Region == region {
			return v, nil
		}
	}
	return Instance{}, oauthError("InvalidRequestException", "invalid_request", "The issuer must identify an Identity Center instance in this Region and partition.", 400)
}

func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Service) exchangeAuthorization(tx Transaction, client Client, in *api.CreateTokenInput) (*api.CreateTokenOutput, error) {
	v, err := tx.AuthorizationByCode(tokenHash(value(in.Code)))
	if err != nil || value(in.Code) == "" || v.State != "AUTHORIZED" || v.ClientID != client.ID || v.RedirectURI != value(in.RedirectUri) || !s.clock.Now().Before(v.Expires) || !validVerifier(value(in.CodeVerifier)) || subtle.ConstantTimeCompare([]byte(v.Challenge), []byte(pkceChallenge(value(in.CodeVerifier)))) != 1 {
		return nil, oauthError("InvalidGrantException", "invalid_grant", "The authorization code or its client, redirect URI, or PKCE verifier is invalid or expired.", 400)
	}
	instance, err := tx.Instance(v.InstanceARN)
	if err != nil || instance.Region != client.Region || instance.Partition != client.Partition || s.currentUser(tx, instance, v.UserID) != nil {
		return nil, oauthError("InvalidGrantException", "invalid_grant", "The authorized directory identity is no longer available.", 400)
	}
	id, err := randomToken()
	if err != nil {
		return nil, err
	}
	refresh := ""
	if slices.Contains(client.GrantTypes, "refresh_token") {
		refresh, err = randomToken()
		if err != nil {
			return nil, err
		}
	}
	now := s.clock.Now()
	out, err := s.issueToken(tx, Session{ID: id, FamilyID: id, ClientID: client.ID, InstanceARN: instance.ARN, UserID: v.UserID, Created: now, RefreshExpires: now.Add(8 * time.Hour)}, refresh)
	if err != nil {
		return nil, err
	}
	v.State = "CONSUMED"
	if err = tx.PutAuthorization(v); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) authorizeCodeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if len(r.URL.RawQuery) > 16<<10 || r.ParseForm() != nil {
		page(w, 400, pageData{Title: "Invalid request", Error: true})
		return
	}
	// Repeated parameters must never be interpreted differently by the browser and token endpoints.
	for _, values := range r.Form {
		if len(values) != 1 {
			page(w, 400, pageData{Title: "Invalid request", Error: true})
			return
		}
	}
	if r.Method == http.MethodGet {
		s.beginAuthorization(w, r)
		return
	}
	var v Authorization
	var client Client
	var instance Instance
	err := s.repository.View(r.Context(), func(rd Reader) error {
		var err error
		v, err = rd.Authorization(r.PostForm.Get("request_id"))
		if err != nil {
			return err
		}
		client, err = rd.Client(v.ClientID)
		if err != nil {
			return err
		}
		instance, err = rd.Instance(v.InstanceARN)
		return err
	})
	if err != nil || v.State != "PENDING" || !s.clock.Now().Before(v.Expires) || !s.clock.Now().Before(client.Expires) {
		page(w, 400, pageData{Title: "Authorization unavailable", Error: true})
		return
	}
	csrf := r.PostForm.Get("csrf")
	cookie, cookieErr := r.Cookie("stackd_sso_pkce_csrf")
	origin := r.Header.Get("Origin")
	endpoint, _ := url.Parse(s.endpoint)
	if cookieErr != nil || csrf == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(v.CSRF)) != 1 || subtle.ConstantTimeCompare([]byte(csrf), []byte(cookie.Value)) != 1 || (origin != "" && (endpoint == nil || origin != endpoint.Scheme+"://"+endpoint.Host)) {
		page(w, 403, pageData{Title: "Authorization rejected", Message: "Reload the sign-in page before trying again.", Error: true})
		return
	}
	decision := r.PostForm.Get("decision")
	if decision != "approve" && decision != "deny" {
		page(w, 400, pageData{Title: "Invalid decision", Error: true})
		return
	}
	username := ""
	if decision == "approve" {
		if s.login == nil {
			page(w, 503, pageData{Title: "Identity source unavailable", Error: true})
			return
		}
		metadata := awsctx.Metadata{Partition: instance.Partition, AccountID: instance.AccountID, Region: instance.Region, SourceIP: r.RemoteAddr, UserAgent: r.UserAgent()}
		username, err = s.login.Authenticate(awsctx.WithMetadata(r.Context(), metadata), r.PostForm.Get("username"), r.PostForm.Get("password"))
		if err != nil {
			page(w, 401, pageData{Title: "Sign-in unsuccessful", Message: "Check your username and password.", Error: true, Authorize: true, ClientName: client.Name, RequestID: v.ID, RedirectURI: v.RedirectURI, CSRF: csrf})
			return
		}
	}
	code := ""
	if decision == "approve" {
		code, err = randomToken()
	}
	if err == nil {
		err = s.repository.Update(r.Context(), func(tx Transaction) error {
			current, err := tx.Authorization(v.ID)
			if err != nil {
				return err
			}
			if current.State != "PENDING" || current.CSRF != csrf || !s.clock.Now().Before(current.Expires) {
				return ErrNotFound
			}
			actual, err := tx.Instance(current.InstanceARN)
			if err != nil {
				return err
			}
			registered, err := tx.Client(current.ClientID)
			if err != nil {
				return err
			}
			if !s.clock.Now().Before(registered.Expires) {
				return ErrNotFound
			}
			current.State = "DENIED"
			if decision == "approve" {
				if s.directory == nil {
					return ErrNotFound
				}
				user, err := s.directory.UserByName(tx.Context(), directoryScope(actual), actual.StoreID, username)
				if err != nil {
					return err
				}
				current.UserID = user.ID
				current.CodeHash = tokenHash(code)
				current.State = "AUTHORIZED"
				current.Expires = s.clock.Now().Add(5 * time.Minute)
			}
			current.CSRF = ""
			return tx.PutAuthorization(current)
		})
	}
	if err != nil {
		page(w, 403, pageData{Title: "Authorization rejected", Message: "The directory identity or authorization request is no longer available.", Error: true})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "stackd_sso_pkce_csrf", Path: AuthorizePath, MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	redirect, _ := url.Parse(v.RedirectURI)
	query := url.Values{}
	if decision == "approve" {
		query.Set("code", code)
	} else {
		query.Set("error", "access_denied")
	}
	query.Set("state", v.OAuthState)
	// The registered URI's query is opaque application data, not necessarily
	// form encoding (an unescaped semicolon is valid URI query content).
	if redirect.RawQuery != "" {
		redirect.RawQuery += "&"
	}
	redirect.RawQuery += query.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}

func (s *Service) beginAuthorization(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var client Client
	var instance Instance
	err := s.repository.View(r.Context(), func(rd Reader) error {
		var err error
		client, err = rd.Client(q.Get("client_id"))
		if err != nil {
			return err
		}
		issuer := client.IssuerURL
		if q.Get("issuer_url") != "" {
			if issuer != "" && issuer != q.Get("issuer_url") {
				return ErrNotFound
			}
			issuer = q.Get("issuer_url")
		}
		instance, err = s.issuerInstance(rd, client.Partition, client.Region, issuer)
		return err
	})
	// Invalid requests are never redirected, including invalid client/redirect pairs.
	challenge, challengeErr := base64.RawURLEncoding.DecodeString(q.Get("code_challenge"))
	if err != nil || !s.clock.Now().Before(client.Expires) || !slices.Contains(client.GrantTypes, "authorization_code") || !registeredRedirect(client.RedirectURIs, q.Get("redirect_uri")) || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || challengeErr != nil || len(challenge) != sha256.Size || base64.RawURLEncoding.EncodeToString(challenge) != q.Get("code_challenge") {
		page(w, 400, pageData{Title: "Invalid authorization request", Message: "Check the registered client, issuer, redirect URI, and S256 challenge.", Error: true})
		return
	}
	requestedScopes := q.Get("scope")
	if q.Has("scopes") {
		if q.Has("scope") && requestedScopes != q.Get("scopes") {
			page(w, 400, pageData{Title: "Invalid scope", Error: true})
			return
		}
		requestedScopes = q.Get("scopes")
	}
	scopes := strings.Fields(requestedScopes)
	if len(scopes) == 0 {
		scopes = client.Scopes
	}
	for _, scope := range scopes {
		if !slices.Contains(client.Scopes, scope) {
			page(w, 400, pageData{Title: "Invalid scope", Error: true})
			return
		}
	}
	id, err := randomToken()
	if err != nil {
		page(w, 500, pageData{Title: "Authorization unavailable", Error: true})
		return
	}
	csrf, err := randomToken()
	if err != nil {
		page(w, 500, pageData{Title: "Authorization unavailable", Error: true})
		return
	}
	now := s.clock.Now()
	v := Authorization{ID: id, ClientID: client.ID, InstanceARN: instance.ARN, RedirectURI: q.Get("redirect_uri"), Challenge: q.Get("code_challenge"), Scope: strings.Join(scopes, " "), OAuthState: q.Get("state"), CSRF: csrf, State: "PENDING", Created: now, Expires: now.Add(10 * time.Minute)}
	err = s.repository.Update(r.Context(), func(tx Transaction) error { return tx.PutAuthorization(v) })
	if err != nil {
		page(w, 500, pageData{Title: "Authorization unavailable", Error: true})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "stackd_sso_pkce_csrf", Value: csrf, Path: AuthorizePath, MaxAge: 600, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	page(w, 200, pageData{Title: "Sign in to Identity Center", ClientName: client.Name, RequestID: id, RedirectURI: v.RedirectURI, CSRF: csrf, Authorize: true})
}
