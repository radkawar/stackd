package appsync

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
	"stackd/clock"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/awsctx"
	"stackd/internal/jwt"
)

func authRecord(mode string) APIRecord {
	return APIRecord{Key: Key{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", ID: "auth-api"}, API: api.GraphqlApi{AuthenticationType: new(api.AuthenticationType(mode))}}
}

func TestAPIKeyExpiryAndLiveRevocation(t *testing.T) {
	ctx := t.Context()
	manual := clock.NewManual(time.Unix(1800000000, 0))
	auth := NewAuthenticator(AuthConfig{Clock: manual})
	record := authRecord("API_KEY")
	request := httptest.NewRequest("POST", "http://localhost/graphql", nil)
	request.Header.Set("x-api-key", "da2-real-key")
	keys := []api.ApiKey{{Id: new(api.String("da2-real-key")), Expires: new(api.Long(manual.Now().Unix() + 60))}}
	identity, err := auth.Authenticate(ctx, record, request, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.refresh(ctx, record, nil); err == nil {
		t.Fatal("deleted API key retained live subscription authority")
	}
	other := record
	other.Key.AccountID = "999999999999"
	if _, err := identity.refresh(ctx, other, keys); err == nil {
		t.Fatal("identity crossed actual resource scope")
	}
	request.Header.Set("x-api-key", "da2-wrong-key")
	if _, err := auth.Authenticate(ctx, record, request, keys); err == nil {
		t.Fatal("wrong key authenticated")
	}
	if err := manual.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.refresh(ctx, record, keys); err == nil {
		t.Fatal("key remained valid at expiration boundary")
	}
}

type authKeySource struct{ keys jwt.KeySet }

func (s *authKeySource) UserPool(context.Context, string, string, string) (jwt.KeySet, error) {
	return s.keys, nil
}
func (s *authKeySource) Issuer(context.Context, string) (jwt.KeySet, error) { return s.keys, nil }

func signedAuthToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"current"}`))
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := header + "." + base64.RawURLEncoding.EncodeToString(body)
	hash := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestJWTSignatureAudienceLifetimeAndKeyRevocation(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	manual := clock.NewManual(now)
	keys := &authKeySource{keys: jwt.KeySet{Issuer: "https://issuer.example", Keys: map[string]*rsa.PublicKey{"current": &private.PublicKey}}}
	auth := NewAuthenticator(AuthConfig{Clock: manual, Keys: keys})
	record := authRecord("OPENID_CONNECT")
	record.API.OpenIDConnectConfig = &api.OpenIDConnectConfig{Issuer: new(api.String(keys.keys.Issuer)), ClientId: new(api.String("client-a|client-b")), IatTTL: new(api.Long(120000))}
	for _, tc := range []struct {
		name    string
		alter   func(map[string]any)
		key     *rsa.PrivateKey
		allowed bool
	}{
		{name: "valid", key: private, allowed: true},
		{name: "different signature", key: wrong},
		{name: "audience substring", key: private, alter: func(c map[string]any) { c["aud"] = "prefix-client-a-suffix" }},
		{name: "authorized party", key: private, alter: func(c map[string]any) { c["aud"] = "other"; c["azp"] = "client-b" }, allowed: true},
		{name: "expiration boundary", key: private, alter: func(c map[string]any) { c["exp"] = now.Unix() }},
		{name: "issued TTL boundary", key: private, alter: func(c map[string]any) { c["iat"] = now.Add(-2 * time.Minute).Unix() }},
		{name: "not yet valid", key: private, alter: func(c map[string]any) { c["nbf"] = now.Add(time.Second).Unix() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"iss": keys.keys.Issuer, "sub": "user-1", "aud": "client-a", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
			if tc.alter != nil {
				tc.alter(claims)
			}
			request := httptest.NewRequest("POST", "http://localhost/graphql", nil)
			request.Header.Set("Authorization", "Bearer "+signedAuthToken(t, tc.key, claims))
			identity, err := auth.Authenticate(t.Context(), record, request, nil)
			if (err == nil) != tc.allowed {
				t.Fatalf("authentication error=%v, allowed=%v", err, tc.allowed)
			}
			if !tc.allowed {
				return
			}
			if identity.Claims["sub"] != "user-1" {
				t.Fatalf("verified subject = %v", identity.Claims["sub"])
			}
			keys.keys.Keys = nil
			if _, err := identity.refresh(t.Context(), record, nil); err == nil {
				t.Fatal("removed signing key retained subscription authority")
			}
			keys.keys.Keys = map[string]*rsa.PublicKey{"current": &private.PublicKey}
		})
	}
}

func TestCognitoClaimsAndFieldDirectivePrecedence(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	keys := &authKeySource{keys: jwt.KeySet{Issuer: "https://cognito.example/us-east-1_pool", Keys: map[string]*rsa.PublicKey{"current": &private.PublicKey}}}
	record := authRecord("AMAZON_COGNITO_USER_POOLS")
	record.API.UserPoolConfig = &api.UserPoolConfig{UserPoolId: new(api.String("us-east-1_pool")), AwsRegion: new(api.String("us-east-1")), AppIdClientRegex: new(api.String("client")), DefaultAction: new(api.DefaultAction("DENY"))}
	claims := map[string]any{"iss": keys.keys.Issuer, "sub": "alice-id", "aud": "client", "token_use": "id", "cognito:username": "alice", "cognito:groups": []string{"Readers"}, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	request := httptest.NewRequest("POST", "http://localhost/graphql", nil)
	request.Header.Set("Authorization", signedAuthToken(t, private, claims))
	auth := NewAuthenticator(AuthConfig{Clock: clock.NewManual(now), Keys: keys})
	identity, err := auth.Authenticate(t.Context(), record, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseSchema(&ast.Source{Input: `type Query { allowed: String @aws_auth(cognito_groups:["Readers"]) denied: String @aws_auth(cognito_groups:["Writers"]) unmarked: String }`})
	if err != nil {
		t.Fatal(err)
	}
	s := NewWithConfig(Config{})
	defer s.Close()
	query := parsed.Definitions.ForName("Query")
	if err := s.checkFieldAuth(t.Context(), identity, record, query, query.Fields.ForName("allowed")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"denied", "unmarked"} {
		if s.checkFieldAuth(t.Context(), identity, record, query, query.Fields.ForName(name)) == nil {
			t.Fatalf("unauthorized %s accepted", name)
		}
	}
	record.API.AdditionalAuthenticationProviders = []api.AdditionalAuthenticationProvider{{AuthenticationType: new(api.AuthenticationType("API_KEY"))}}
	parsed, err = parser.ParseSchema(&ast.Source{Input: `type Query @aws_api_key { restricted: String @aws_cognito_user_pools(cognito_groups:["Readers"]) shared: String }`})
	if err != nil {
		t.Fatal(err)
	}
	query = parsed.Definitions.ForName("Query")
	if s.checkFieldAuth(t.Context(), Identity{Mode: "API_KEY"}, record, query, query.Fields.ForName("restricted")) == nil {
		t.Fatal("type grant overrode narrower field directive")
	}
	if err := s.checkFieldAuth(t.Context(), identity, record, query, query.Fields.ForName("restricted")); err != nil {
		t.Fatal(err)
	}
	if err := s.checkFieldAuth(t.Context(), Identity{Mode: "API_KEY"}, record, query, query.Fields.ForName("shared")); err != nil {
		t.Fatal(err)
	}
	claims["iss"] = "https://other.example"
	request.Header.Set("Authorization", signedAuthToken(t, private, claims))
	if _, err := auth.Authenticate(t.Context(), record, request, nil); err == nil {
		t.Fatal("wrong Cognito issuer accepted with a trusted signing key")
	}
}

type authPolicySource struct{ document string }

func (s *authPolicySource) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{Identity: []policy.Policy{{Document: s.document}}}, nil
}

func TestIAMFieldARNAndCurrentExplicitDeny(t *testing.T) {
	record := authRecord("AWS_IAM")
	record.Schema = `schema { query: Root } type Root { allowed: Thing denied: Thing } type Thing { id: ID }`
	resource := record.Key.ARN() + "/types/Root/fields/allowed"
	policies := &authPolicySource{document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"appsync:GraphQL","Resource":"` + resource + `"}]}`}
	s := NewWithConfig(Config{Authorizer: authorization.New(policies, nil)})
	defer s.Close()
	identity := Identity{Mode: "AWS_IAM", Context: awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: record.Key.AccountID, Region: record.Key.Region, PrincipalID: "AIDAEXAMPLE", PrincipalARN: "arn:aws:iam::123456789012:user/reader", UserName: "reader"})}
	parent := &ast.Definition{Name: "Root"}
	if err := s.checkFieldAuth(t.Context(), identity, record, parent, &ast.FieldDefinition{Name: "allowed"}); err != nil {
		t.Fatal(err)
	}
	if err := s.checkFieldAuth(t.Context(), identity, record, &ast.Definition{Name: "Thing"}, &ast.FieldDefinition{Name: "id"}); err != nil {
		t.Fatalf("root grant did not cover nested selection: %v", err)
	}
	if s.checkFieldAuth(t.Context(), identity, record, parent, &ast.FieldDefinition{Name: "denied"}) == nil {
		t.Fatal("field-scoped IAM grant authorized another field")
	}
	policies.document = strings.Replace(policies.document, `"Allow"`, `"Deny"`, 1)
	if s.checkFieldAuth(t.Context(), identity, record, parent, &ast.FieldDefinition{Name: "allowed"}) == nil {
		t.Fatal("current explicit IAM denial was not applied")
	}
}
