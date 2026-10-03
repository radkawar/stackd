package appsync

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/ast"
	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/jwt"
)

// Authenticator authenticates against the actual API, never a caller-selected account.
type Authenticator interface {
	Authenticate(context.Context, APIRecord, *http.Request, []api.ApiKey) (Identity, error)
}

// Identity carries verified claims. Its private refresh function rechecks current
// authority for live subscriptions without treating an old SigV4 date as a new request.
type Identity struct {
	Mode            string
	Claims          map[string]any
	Context         context.Context
	defaultStrategy string
	refresh         func(context.Context, APIRecord, []api.ApiKey) (Identity, error)
}

// IAMAuthentication delegates signatures and current credential admission to the
// shared gateway/identity owners. Implementations must not introduce a verifier.
type IAMAuthentication interface {
	Authenticate(*http.Request, string, string) (*http.Request, *awswire.Error)
	Revalidate(context.Context) error
}

// KeySource returns only keys selected by API configuration, not JWT headers.
type KeySource interface {
	UserPool(context.Context, string, string, string) (jwt.KeySet, error)
	Issuer(context.Context, string) (jwt.KeySet, error)
}

type AuthConfig struct {
	Clock clock.Clock
	IAM   IAMAuthentication
	Keys  KeySource
}

type authenticator struct{ config AuthConfig }

func NewAuthenticator(config AuthConfig) Authenticator {
	if config.Clock == nil {
		config.Clock = clock.Real{}
	}
	return &authenticator{config: config}
}

func authDenied() error {
	return &awswire.Error{Code: "UnauthorizedException", Message: "You are not authorized to make this call.", StatusCode: http.StatusUnauthorized}
}

func authModeConfigured(record APIRecord, mode string) bool {
	if value(record.API.AuthenticationType) == mode {
		return true
	}
	for _, provider := range record.API.AdditionalAuthenticationProviders {
		if value(provider.AuthenticationType) == mode {
			return true
		}
	}
	return false
}

type resolverRequestKey struct{}

func (a *authenticator) Authenticate(ctx context.Context, record APIRecord, r *http.Request, keys []api.ApiKey) (Identity, error) {
	headers := make(map[string]any, len(r.Header)+1)
	for name, values := range r.Header {
		if strings.EqualFold(name, "Cookie") {
			continue
		}
		if len(values) == 1 {
			headers[strings.ToLower(name)] = values[0]
		} else {
			headers[strings.ToLower(name)] = values
		}
	}
	headers["host"] = r.Host
	ctx = context.WithValue(ctx, resolverRequestKey{}, map[string]any{"headers": headers, "domainName": nil})
	if key := r.Header.Get("x-api-key"); key != "" {
		return a.apiKey(ctx, record, key, keys)
	}
	authorizationHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authorizationHeader, "AWS4-HMAC-SHA256 ") || r.URL.Query().Get("X-Amz-Algorithm") != "" {
		if !authModeConfigured(record, "AWS_IAM") || a.config.IAM == nil {
			return Identity{}, authDenied()
		}
		verified, failure := a.config.IAM.Authenticate(r.WithContext(ctx), "appsync", record.Key.Region)
		if failure != nil {
			return Identity{}, authDenied()
		}
		if awsctx.FromContext(verified.Context()).Partition != record.Key.Partition {
			return Identity{}, authDenied()
		}
		// Gateway restores the body on its authenticated request copy. Preserve
		// that stream for the HTTP executor after signature verification.
		r.Body = verified.Body
		identity := Identity{Mode: "AWS_IAM", Context: verified.Context()}
		metadata := awsctx.FromContext(verified.Context())
		identity.refresh = func(current context.Context, target APIRecord, _ []api.ApiKey) (Identity, error) {
			if target.Key != record.Key || !authModeConfigured(target, "AWS_IAM") {
				return Identity{}, authDenied()
			}
			current = awsctx.WithMetadata(current, metadata)
			if err := a.config.IAM.Revalidate(current); err != nil {
				return Identity{}, authDenied()
			}
			result := identity
			result.Context = current
			return result, nil
		}
		return identity, nil
	}
	authorizationHeader = strings.TrimPrefix(authorizationHeader, "Bearer ")
	return a.token(ctx, record, authorizationHeader, r.RemoteAddr)
}

func (a *authenticator) apiKey(ctx context.Context, record APIRecord, secret string, keys []api.ApiKey) (Identity, error) {
	if !authModeConfigured(record, "API_KEY") {
		return Identity{}, authDenied()
	}
	for _, key := range keys {
		if subtle.ConstantTimeCompare([]byte(secret), []byte(value(key.Id))) != 1 || key.Expires == nil || a.config.Clock.Now().Unix() >= int64(*key.Expires) {
			continue
		}
		identity := Identity{Mode: "API_KEY", Context: ctx}
		identity.refresh = func(current context.Context, target APIRecord, currentKeys []api.ApiKey) (Identity, error) {
			if target.Key != record.Key {
				return Identity{}, authDenied()
			}
			return a.apiKey(current, target, secret, currentKeys)
		}
		return identity, nil
	}
	return Identity{}, authDenied()
}

type tokenProvider struct {
	mode, poolID, region, clientPattern string
	oidc                                *api.OpenIDConnectConfig
	defaultStrategy                     string
}

func tokenProviders(record APIRecord) []tokenProvider {
	providers := make([]tokenProvider, 0, 1+len(record.API.AdditionalAuthenticationProviders))
	if value(record.API.AuthenticationType) == "AMAZON_COGNITO_USER_POOLS" && record.API.UserPoolConfig != nil {
		p := record.API.UserPoolConfig
		providers = append(providers, tokenProvider{mode: "AMAZON_COGNITO_USER_POOLS", poolID: value(p.UserPoolId), region: value(p.AwsRegion), clientPattern: value(p.AppIdClientRegex), defaultStrategy: value(p.DefaultAction)})
	}
	if value(record.API.AuthenticationType) == "OPENID_CONNECT" && record.API.OpenIDConnectConfig != nil {
		providers = append(providers, tokenProvider{mode: "OPENID_CONNECT", oidc: record.API.OpenIDConnectConfig, clientPattern: value(record.API.OpenIDConnectConfig.ClientId)})
	}
	for _, p := range record.API.AdditionalAuthenticationProviders {
		if value(p.AuthenticationType) == "AMAZON_COGNITO_USER_POOLS" && p.UserPoolConfig != nil {
			providers = append(providers, tokenProvider{mode: "AMAZON_COGNITO_USER_POOLS", poolID: value(p.UserPoolConfig.UserPoolId), region: value(p.UserPoolConfig.AwsRegion), clientPattern: value(p.UserPoolConfig.AppIdClientRegex)})
		}
		if value(p.AuthenticationType) == "OPENID_CONNECT" && p.OpenIDConnectConfig != nil {
			providers = append(providers, tokenProvider{mode: "OPENID_CONNECT", oidc: p.OpenIDConnectConfig, clientPattern: value(p.OpenIDConnectConfig.ClientId)})
		}
	}
	return providers
}

func (a *authenticator) token(ctx context.Context, record APIRecord, raw, remote string) (Identity, error) {
	// TODO: Comeback support the additional native OIDC PS/ES/HS algorithms and
	// Lambda authorizers. Unsupported algorithms never become unsigned claims.
	parsed, err := jwt.Parse(raw, func(algorithm string) bool {
		return algorithm == "RS256" || algorithm == "RS384" || algorithm == "RS512"
	})
	if err != nil || a.config.Keys == nil {
		return Identity{}, authDenied()
	}
	now := a.config.Clock.Now()
	expires, ok := tokenTime(parsed, "exp")
	if !ok || !now.Before(expires) {
		return Identity{}, authDenied()
	}
	issued, ok := tokenTime(parsed, "iat")
	if !ok || issued.After(now) {
		return Identity{}, authDenied()
	}
	if _, exists := parsed.Claims["nbf"]; exists {
		notBefore, ok := tokenTime(parsed, "nbf")
		if !ok || notBefore.After(now) {
			return Identity{}, authDenied()
		}
	}
	issuer, _ := jwt.String(parsed.Claims, "iss")
	for _, provider := range tokenProviders(record) {
		var keys jwt.KeySet
		var err error
		if provider.oidc != nil {
			keys, err = a.config.Keys.Issuer(ctx, value(provider.oidc.Issuer))
			if err == nil && keys.Issuer != value(provider.oidc.Issuer) {
				continue
			}
		} else {
			keys, err = a.config.Keys.UserPool(ctx, record.Key.Partition, provider.region, provider.poolID)
		}
		if err != nil {
			continue
		}
		// Native single-mode OIDC skips the iss comparison, but still obtains
		// signing keys exclusively from the configured authoritative issuer.
		singleOIDC := provider.oidc != nil && value(record.API.AuthenticationType) == "OPENID_CONNECT" && len(record.API.AdditionalAuthenticationProviders) == 0
		if !singleOIDC && issuer != keys.Issuer {
			continue
		}
		key := keys.Keys[parsed.KeyID]
		if key == nil || jwt.VerifyRSA(parsed, key) != nil {
			continue
		}
		if provider.oidc == nil {
			use, _ := jwt.String(parsed.Claims, "token_use")
			if parsed.Algorithm != "RS256" || (use != "access" && use != "id") {
				continue
			}
			claim := "aud"
			if use == "access" {
				claim = "client_id"
			}
			if !tokenClientMatches(parsed, provider.clientPattern, claim) {
				continue
			}
		} else {
			if !tokenClientMatches(parsed, provider.clientPattern, "aud", "azp") {
				continue
			}
			if provider.oidc.IatTTL != nil && *provider.oidc.IatTTL > 0 && now.Sub(issued).Milliseconds() >= int64(*provider.oidc.IatTTL) {
				continue
			}
			if provider.oidc.AuthTTL != nil && *provider.oidc.AuthTTL > 0 {
				authTime, ok := tokenTime(parsed, "auth_time")
				if !ok || authTime.After(now) || now.Sub(authTime).Milliseconds() >= int64(*provider.oidc.AuthTTL) {
					continue
				}
			}
		}
		claims := make(map[string]any, len(parsed.Claims))
		for name, rawClaim := range parsed.Claims {
			var claim any
			if json.Unmarshal(rawClaim, &claim) != nil {
				return Identity{}, authDenied()
			}
			claims[name] = claim
		}
		ip, _, _ := net.SplitHostPort(remote)
		identity := Identity{Mode: provider.mode, Claims: claims, Context: awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: record.Key.Partition, Region: record.Key.Region, AccountID: record.Key.AccountID, SourceIP: ip}), defaultStrategy: provider.defaultStrategy}
		identity.refresh = func(current context.Context, target APIRecord, _ []api.ApiKey) (Identity, error) {
			if target.Key != record.Key {
				return Identity{}, authDenied()
			}
			return a.token(current, target, raw, remote)
		}
		return identity, nil
	}
	return Identity{}, authDenied()
}

func tokenTime(token jwt.Token, name string) (time.Time, bool) {
	var seconds json.Number
	if json.Unmarshal(token.Claims[name], &seconds) != nil {
		return time.Time{}, false
	}
	n, err := seconds.Int64()
	if err != nil || n < 0 {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

func tokenClientMatches(token jwt.Token, pattern string, names ...string) bool {
	if pattern == "" {
		return true
	}
	compiled, err := regexp.Compile("^(?:" + pattern + ")$")
	if err != nil {
		return false
	}
	for _, name := range names {
		if claim, ok := jwt.String(token.Claims, name); ok && compiled.MatchString(claim) {
			return true
		}
		var claims []string
		if json.Unmarshal(token.Claims[name], &claims) == nil {
			for _, claim := range claims {
				if compiled.MatchString(claim) {
					return true
				}
			}
		}
	}
	return false
}

func (s *Service) checkFieldAuth(ctx context.Context, identity Identity, record APIRecord, parent *ast.Definition, field *ast.FieldDefinition) error {
	if parent == nil || field == nil || !authModeConfigured(record, identity.Mode) {
		return authDenied()
	}
	directives := field.Directives
	if !hasAuthDirectives(record, directives) {
		directives = parent.Directives
	}
	allowed := identity.Mode == value(record.API.AuthenticationType)
	if hasAuthDirectives(record, directives) {
		allowed = false
		for _, directive := range directives {
			if !authDirectiveApplies(record, directive.Name) {
				continue
			}
			mode := directiveAuthMode(directive.Name)
			if mode != identity.Mode {
				continue
			}
			if mode == "AMAZON_COGNITO_USER_POOLS" && !matchesGroups(identity.Claims, directive) {
				continue
			}
			allowed = true
		}
	} else if identity.Mode == "AMAZON_COGNITO_USER_POOLS" && identity.defaultStrategy == "DENY" {
		allowed = false
	}
	if !allowed {
		return fmt.Errorf("not authorized to access %s on type %s: %w", field.Name, parent.Name, authDenied())
	}
	if identity.Mode == "AWS_IAM" {
		if identity.Context == nil {
			return authDenied()
		}
		// Native iamRootFieldOnly fixture permits nested selections with only
		// the operation-root field ARN. Schema directives still apply above.
		schema, err := s.compiled(record)
		if err != nil {
			return err
		}
		root := false
		for _, candidate := range []*ast.Definition{schema.Query, schema.Mutation, schema.Subscription} {
			if candidate != nil && candidate.Name == parent.Name {
				root = true
				break
			}
		}
		if !root {
			return nil
		}
		ctx = awsctx.WithMetadata(ctx, awsctx.FromContext(identity.Context))
		conditions := make(map[string][]string, len(record.API.Tags))
		for key, val := range record.API.Tags {
			conditions["aws:ResourceTag/"+string(key)] = []string{string(val)}
		}
		if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: "appsync:GraphQL", ResourceARN: record.Key.ARN() + "/types/" + parent.Name + "/fields/" + field.Name, ResourceAccountID: record.Key.AccountID, Context: conditions}); denied != nil {
			return denied
		}
	}
	return nil
}

func directiveAuthMode(name string) string {
	switch name {
	case "aws_api_key":
		return "API_KEY"
	case "aws_iam":
		return "AWS_IAM"
	case "aws_oidc":
		return "OPENID_CONNECT"
	case "aws_cognito_user_pools", "aws_auth":
		return "AMAZON_COGNITO_USER_POOLS"
	case "aws_lambda":
		return "AWS_LAMBDA"
	}
	return ""
}

func hasAuthDirectives(record APIRecord, all ast.DirectiveList) bool {
	for _, directive := range all {
		if authDirectiveApplies(record, directive.Name) {
			return true
		}
	}
	return false
}

func authDirectiveApplies(record APIRecord, name string) bool {
	switch name {
	case "aws_auth":
		return len(record.API.AdditionalAuthenticationProviders) == 0 && value(record.API.AuthenticationType) == "AMAZON_COGNITO_USER_POOLS"
	case "aws_cognito_user_pools":
		return len(record.API.AdditionalAuthenticationProviders) != 0
	default:
		return directiveAuthMode(name) != ""
	}
}

func matchesGroups(claims map[string]any, directive *ast.Directive) bool {
	argument := directive.Arguments.ForName("cognito_groups")
	if argument == nil {
		return true
	}
	groups, err := argument.Value.Value(nil)
	if err != nil {
		return false
	}
	required, ok := groups.([]any)
	if !ok {
		return false
	}
	if len(required) == 0 {
		return true
	}
	actual, _ := claims["cognito:groups"].([]any)
	for _, want := range required {
		for _, have := range actual {
			if want == have {
				return true
			}
		}
	}
	return false
}

func identityContext(identity Identity) map[string]any {
	if identity.Mode == "API_KEY" {
		return nil
	}
	if identity.Mode == "AWS_IAM" {
		if identity.Context == nil {
			return nil
		}
		m := awsctx.FromContext(identity.Context)
		result := map[string]any{"accountId": m.AccountID, "userArn": m.PrincipalARN, "username": m.UserName, "sourceIp": []string{m.SourceIP}}
		for claim, name := range map[string]string{"cognito-identity.amazonaws.com:sub": "cognitoIdentityId", "cognito-identity.amazonaws.com:aud": "cognitoIdentityPoolId", "cognito-identity.amazonaws.com:amr": "cognitoIdentityAuthType"} {
			if values := m.SessionContext[claim]; len(values) > 0 {
				result[name] = values[0]
			}
		}
		return result
	}
	result := map[string]any{"claims": identity.Claims, "sub": identity.Claims["sub"], "issuer": identity.Claims["iss"]}
	if identity.Mode == "AMAZON_COGNITO_USER_POOLS" {
		username := identity.Claims["cognito:username"]
		if username == nil {
			username = identity.Claims["username"]
		}
		result["username"] = username
		strategy := identity.defaultStrategy
		if strategy == "" {
			strategy = "ALLOW"
		}
		result["defaultAuthStrategy"] = strategy
	}
	if identity.Context != nil {
		ip := awsctx.FromContext(identity.Context).SourceIP
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
		result["sourceIp"] = []string{ip}
	}
	return result
}
