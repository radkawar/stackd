package sts

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"stackd/clock"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"

	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/gateway"
	"stackd/internal/identity"
)

type oidcHandlerAuthority struct {
	mu       sync.Mutex
	provider OIDCProviderSnapshot
	keys     OIDCKeySet
	role     RoleSnapshot
	store    *identity.Store
	before   func()
	loaded   int
	issued   int
	metadata awsctx.Metadata
}

func (a *oidcHandlerAuthority) OIDCProviderForFederation(ctx context.Context, arn string) (OIDCProviderSnapshot, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.metadata = awsctx.FromContext(ctx)
	if arn != a.provider.ARN {
		return OIDCProviderSnapshot{}, ErrFederationProviderNotFound
	}
	return a.provider, nil
}
func (a *oidcHandlerAuthority) ResolveOIDCSigningKeys(_ context.Context, arn string) (OIDCKeySet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.loaded++
	if arn != a.provider.ARN {
		return OIDCKeySet{}, ErrFederationProviderNotFound
	}
	return cloneOIDCKeySet(a.keys), nil
}
func (a *oidcHandlerAuthority) RoleForAssumption(_ context.Context, arn string) (RoleSnapshot, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if arn != a.role.ARN {
		return RoleSnapshot{}, errors.New("role not found")
	}
	return a.role, nil
}
func (*oidcHandlerAuthority) ResolveManagedPolicyDocuments(context.Context, []string) ([]string, error) {
	return nil, errors.New("managed policy not found")
}
func (a *oidcHandlerAuthority) WithFederationSession(ctx context.Context, ref FederationProviderReference, roleARN string, fn func(context.Context, RoleSnapshot, FederatedCredentialIssuer) error) error {
	if a.before != nil {
		a.before()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if ref.ARN != a.provider.ARN || ref.ID != a.provider.ID || ref.Version != a.provider.Version {
		return invalidOIDCToken("The provider changed before credentials could be issued.")
	}
	if roleARN != a.role.ARN {
		return stsDenied("The role no longer exists.")
	}
	if err := fn(ctx, a.role, a.store); err != nil {
		return err
	}
	a.issued++
	return nil
}

func oidcHandlerClient(t *testing.T, a *oidcHandlerAuthority, now time.Time, oauth OAuthTokenSource) (*sdksts.Client, *httptest.Server) {
	t.Helper()
	service := NewWithDependencies(Dependencies{Credentials: a.store, Sessions: credentialAuthority{a.store}, Roles: a, OIDCProviders: a, OAuthTokens: oauth, Federation: a, Clock: clock.NewManual(now)})
	model, _ := awscatalog.LookupService("sts")
	registry := &gateway.Registry{}
	if err := registry.Register(gateway.Service{Name: "sts", SigningName: "sts", Protocol: gateway.Query, QueryVersion: "2011-06-15", Namespace: Namespace, Provider: service, Model: &model, Decode: stsapi.DecodeRequest}); err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(registry, gateway.Config{Credentials: a.store})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g)
	t.Cleanup(server.Close)
	return sdksts.New(sdksts.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), Retryer: aws.NopRetryer{}}), server
}

func oidcHandlerFixture(t *testing.T, scenario string) (*oidcHandlerAuthority, *sdksts.AssumeRoleWithWebIdentityInput, time.Time) {
	t.Helper()
	data, err := os.ReadFile("testdata/oidc/aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Issuer    string
		Scenarios []struct {
			Scenario   string
			ObservedAt string `json:"observed_at"`
			Input      struct {
				WebIdentityToken, RoleSessionName string
				ProviderId                        *string
				DurationSeconds                   *int32
			}
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Scenarios {
		if row.Scenario != scenario {
			continue
		}
		now, err := time.Parse(time.RFC3339Nano, row.ObservedAt)
		if err != nil {
			t.Fatal(err)
		}
		provider := OIDCProviderSnapshot{ARN: "arn:aws:iam::123456789012:oidc-provider/" + strings.TrimPrefix(fixture.Issuer, "https://"), ID: "OIDCHANDLER", Version: "1", IssuerURL: fixture.Issuer, ClientIDs: []string{"client-a", "client-b"}}
		a := &oidcHandlerAuthority{provider: provider, keys: OIDCKeySet{IssuerURL: fixture.Issuer, ProviderID: provider.ID, ProviderVersion: provider.Version, Keys: oidcFixtureKeys(t), CacheUntil: now.Add(time.Hour)}, role: RoleSnapshot{ARN: "arn:aws:iam::123456789012:role/path/web-role", ID: "AROAWEBSERVICE", Name: "web-role", MaxSessionDuration: 2 * time.Hour}, store: identity.NewStore("123456789012")}
		a.role.TrustPolicy = fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":["sts:AssumeRoleWithWebIdentity","sts:TagSession","sts:SetSourceIdentity"],"Condition":{"StringEquals":{%q:"client-a"}}}]}`, provider.ARN, strings.TrimPrefix(fixture.Issuer, "https://")+":aud")
		return a, &sdksts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String(a.role.ARN), RoleSessionName: aws.String(row.Input.RoleSessionName), WebIdentityToken: aws.String(row.Input.WebIdentityToken), DurationSeconds: row.Input.DurationSeconds, ProviderId: row.Input.ProviderId}, now
	}
	t.Fatalf("missing scenario %s", scenario)
	return nil, nil, time.Time{}
}

func oidcHandlerError(t *testing.T, err error, code string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != code {
		t.Fatalf("error=%v; want %s", err, code)
	}
}

func TestOIDCSDKFederationCredentialsAndClaims(t *testing.T) {
	for _, scenario := range []string{"algorithm-RS256", "algorithm-RS384", "algorithm-RS512", "algorithm-ES256", "algorithm-ES384", "algorithm-ES512", "subject-empty", "subject-short", "azp-overrides", "token-expiry-does-not-cap-session"} {
		t.Run(scenario, func(t *testing.T) {
			a, input, now := oidcHandlerFixture(t, scenario)
			audience := "client-a"
			if scenario == "azp-overrides" {
				audience = "client-b"
				a.role.TrustPolicy = strings.Replace(a.role.TrustPolicy, `:"client-a"`, `:"client-b"`, 1)
			}
			client, server := oidcHandlerClient(t, a, now, nil)
			out, err := client.AssumeRoleWithWebIdentity(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if out.Credentials == nil || out.AssumedRoleUser == nil || aws.ToString(out.Provider) != a.provider.ARN || aws.ToString(out.Audience) != audience || out.SubjectFromWebIdentityToken == nil || out.PackedPolicySize == nil {
				t.Fatalf("missing or incorrect generated output: %+v", out)
			}
			c, err := a.store.Resolve(context.Background(), aws.ToString(out.Credentials.AccessKeyId))
			if err != nil {
				t.Fatal(err)
			}
			if c.SessionToken != aws.ToString(out.Credentials.SessionToken) || c.PrincipalARN != aws.ToString(out.AssumedRoleUser.Arn) || c.PrincipalID != "AROAWEBSERVICE:"+aws.ToString(input.RoleSessionName) || c.IssuerARN != a.role.ARN || c.IssuerID != a.role.ID || c.SessionType != identity.SessionTypeAssumeRole {
				t.Fatal("returned credentials do not identify the authorized role")
			}
			want := time.Hour
			if input.DurationSeconds != nil {
				want = time.Duration(*input.DurationSeconds) * time.Second
			}
			if c.Expiration.Sub(c.CreateDate) != want {
				t.Fatalf("session duration=%s; want %s", c.Expiration.Sub(c.CreateDate), want)
			}
			prefix := strings.TrimPrefix(a.provider.IssuerURL, "https://")
			if len(c.SessionContext[prefix+":sub"]) != 1 || c.SessionContext[prefix+":sub"][0] != aws.ToString(out.SubjectFromWebIdentityToken) || len(c.SessionContext[prefix+":oaud"]) != 0 {
				t.Fatalf("wrong downstream claim context: %+v", c.SessionContext)
			}
			if a.metadata.AccountID != "123456789012" || a.metadata.Partition != "aws" || a.metadata.PrincipalARN != "" || a.metadata.AccessKeyID != "" || !a.metadata.TransportKnown {
				t.Fatalf("provider lookup scope fabricated a caller: %+v", a.metadata)
			}
			// Exercise SigV4 with the actual stored secret and security token.
			signed := sdksts.New(sdksts.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken), Retryer: aws.NopRetryer{}})
			who, err := signed.GetCallerIdentity(context.Background(), &sdksts.GetCallerIdentityInput{})
			if err != nil || aws.ToString(who.Arn) != c.PrincipalARN || aws.ToString(who.Account) != "123456789012" {
				t.Fatalf("issued credentials cannot authenticate: %v %+v", err, who)
			}
			_, err = signed.GetSessionToken(context.Background(), &sdksts.GetSessionTokenInput{})
			oidcHandlerError(t, err, "AccessDenied")
		})
	}
}

func TestOIDCSDKRejectsTokensAndTrustChanges(t *testing.T) {
	for _, scenario := range []struct{ name, code string }{{"missing-sub", "InvalidIdentityToken"}, {"expired-301", "ExpiredTokenException"}, {"azp-mismatch", "InvalidIdentityToken"}, {"unknown-key-id", "InvalidIdentityToken"}, {"provider-id-with-oidc", "InvalidIdentityToken"}} {
		t.Run(scenario.name, func(t *testing.T) {
			a, input, now := oidcHandlerFixture(t, scenario.name)
			client, _ := oidcHandlerClient(t, a, now, nil)
			_, err := client.AssumeRoleWithWebIdentity(context.Background(), input)
			oidcHandlerError(t, err, scenario.code)
			if scenario.code == "ExpiredTokenException" {
				var modeled *ststypes.ExpiredTokenException
				if !errors.As(err, &modeled) {
					t.Fatalf("unmodeled expiry error: %v", err)
				}
			}
			if a.issued != 0 {
				t.Fatal("invalid token issued credentials")
			}
		})
	}
	for _, kind := range []string{"provider deleted", "provider recreated", "provider changed", "role changed", "audience trust", "AWS wildcard principal", "duration exceeds role", "malformed policy", "different account", "different partition", "non-role ARN", "missing TagSession", "missing SetSourceIdentity"} {
		t.Run(kind, func(t *testing.T) {
			a, input, now := oidcHandlerFixture(t, "algorithm-RS256")
			code := "AccessDenied"
			switch kind {
			case "provider deleted":
				a.provider.ARN = ""
				code = "InvalidIdentityToken"
			case "provider recreated", "provider changed":
				a.before = func() {
					a.mu.Lock()
					defer a.mu.Unlock()
					if kind == "provider recreated" {
						a.provider.ID = "replacement"
					} else {
						a.provider.Version = "2"
					}
				}
				code = "InvalidIdentityToken"
			case "role changed":
				a.before = func() {
					a.mu.Lock()
					defer a.mu.Unlock()
					a.role.TrustPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`
				}
			case "audience trust":
				a.role.TrustPolicy = strings.Replace(a.role.TrustPolicy, `:"client-a"`, `:"untrusted-client"`, 1)
			case "AWS wildcard principal":
				a.role.TrustPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`
			case "duration exceeds role":
				input.DurationSeconds = aws.Int32(10800)
				code = "ValidationError"
			case "malformed policy":
				input.Policy = aws.String("bad policy")
				code = "MalformedPolicyDocument"
			case "different account":
				input.RoleArn = aws.String(strings.Replace(a.role.ARN, "123456789012", "210987654321", 1))
				code = "InvalidIdentityToken"
			case "different partition":
				input.RoleArn = aws.String(strings.Replace(a.role.ARN, "arn:aws:", "arn:aws-cn:", 1))
				code = "InvalidIdentityToken"
			case "non-role ARN":
				input.RoleArn = aws.String(strings.Replace(a.role.ARN, ":role/", ":user/", 1))
				code = "ValidationError"
			case "missing TagSession", "missing SetSourceIdentity":
				claims := oidcHandlerClaims(t, input)
				if kind == "missing TagSession" {
					claims["https://aws.amazon.com/tags"] = map[string]any{"principal_tags": map[string]any{"team": []string{"blue"}}}
					a.role.TrustPolicy = strings.Replace(a.role.TrustPolicy, `,"sts:TagSession"`, "", 1)
				} else {
					claims["https://aws.amazon.com/source_identity"] = "source-web"
					a.role.TrustPolicy = strings.Replace(a.role.TrustPolicy, `,"sts:SetSourceIdentity"`, "", 1)
				}
				input.WebIdentityToken = aws.String(signOIDCHandlerClaims(t, claims))
			}
			client, _ := oidcHandlerClient(t, a, now, nil)
			_, err := client.AssumeRoleWithWebIdentity(context.Background(), input)
			oidcHandlerError(t, err, code)
			if a.issued != 0 {
				t.Fatal("failed authorization issued credentials")
			}
		})
	}
}

func oidcHandlerClaims(t *testing.T, input *sdksts.AssumeRoleWithWebIdentityInput) map[string]any {
	t.Helper()
	token, apiErr := parseOIDCJWT(aws.ToString(input.WebIdentityToken))
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	claims := map[string]any{}
	for key, raw := range token.Claims {
		claims[key] = raw
	}
	return claims
}

func signOIDCHandlerClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	data, err := os.ReadFile("testdata/oidc/rsa2048.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("invalid signing fixture")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("not an RSA signing fixture")
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString(body)
	hash := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestOIDCSDKSessionClaimsAndBuiltinProviders(t *testing.T) {
	for _, provider := range []string{"custom", "accounts.google.com", "cognito-identity.amazonaws.com"} {
		t.Run(provider, func(t *testing.T) {
			a, input, now := oidcHandlerFixture(t, "algorithm-RS256")
			claims := oidcHandlerClaims(t, input)
			claims["https://aws.amazon.com/source_identity"] = "source-web"
			claims["https://aws.amazon.com/tags"] = map[string]any{"principal_tags": map[string]any{"team": []string{"blue"}}, "transitive_tag_keys": []string{"team"}}
			claims["amr"] = []string{"pwd", "mfa"}
			claims["email"] = "fixture@example.test"
			claims["aws:PrincipalArn"] = "arn:aws:iam::123456789012:root"
			if provider != "custom" {
				a.provider.ARN, a.provider.ID, a.provider.Version = provider, provider, "builtin-v1"
				a.provider.IssuerURL = "https://" + provider
				a.provider.ClientIDs = nil
				a.keys.ProviderID, a.keys.ProviderVersion, a.keys.IssuerURL = provider, "builtin-v1", a.provider.IssuerURL
				claims["iss"] = a.provider.IssuerURL
				if provider == "accounts.google.com" {
					claims["iss"] = provider
				}
				a.role.TrustPolicy = fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":["sts:AssumeRoleWithWebIdentity","sts:TagSession","sts:SetSourceIdentity"],"Condition":{"StringEquals":{%q:"client-a"}}}]}`, provider, provider+":aud")
			}
			input.WebIdentityToken = aws.String(signOIDCHandlerClaims(t, claims))
			input.Policy = aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
			client, _ := oidcHandlerClient(t, a, now, nil)
			out, err := client.AssumeRoleWithWebIdentity(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			c, err := a.store.Resolve(context.Background(), aws.ToString(out.Credentials.AccessKeyId))
			if err != nil {
				t.Fatal(err)
			}
			prefix := strings.TrimPrefix(a.provider.IssuerURL, "https://")
			if c.SourceIdentity != "source-web" || aws.ToString(out.SourceIdentity) != "source-web" || c.SessionTags["team"] != "blue" || len(c.TransitiveTagKeys) != 1 || len(c.SessionContext) != 3 || len(c.SessionContext[prefix+":amr"]) != 2 || len(c.SessionPolicies) != 1 || !c.HasSessionPolicy || aws.ToString(out.Provider) != a.provider.ARN {
				t.Fatal("verified source identity, session tags, policy or context not persisted")
			}
		})
	}
}

func TestOIDCSDKOAuthUsesConfiguredIntrospection(t *testing.T) {
	for _, provider := range []string{"www.amazon.com", "graph.facebook.com"} {
		t.Run(provider, func(t *testing.T) {
			a, input, now := oidcHandlerFixture(t, "algorithm-RS256")
			a.provider = OIDCProviderSnapshot{ARN: provider, ID: provider, Version: "builtin-v1"}
			a.role.TrustPolicy = fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{%q:"application-id"}}}]}`, provider, provider+":app_id")
			idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if provider == "www.amazon.com" {
					if r.URL.Query().Get("access_token") != "opaque-fixture-token" {
						t.Error("missing token introspection")
					}
					_, _ = w.Write([]byte(`{"iss":"https://www.amazon.com","user_id":"subject-web","aud":"client-id","app_id":"application-id","exp":300}`))
				} else {
					if r.URL.Query().Get("input_token") != "opaque-fixture-token" || r.URL.Query().Get("access_token") != "configured-app-token" {
						t.Error("missing Facebook introspection credentials")
					}
					_, _ = w.Write([]byte(`{"data":{"is_valid":true,"type":"USER","user_id":"subject-web","app_id":"application-id","expires_at":0}}`))
				}
			}))
			defer idp.Close()
			source, err := NewHTTPOAuthTokenSource(OAuthHTTPConfig{Client: idp.Client(), AmazonTokenInfoURL: idp.URL, FacebookDebugTokenURL: idp.URL, FacebookAppAccessToken: "configured-app-token", Clock: clock.NewManual(now)})
			if err != nil {
				t.Fatal(err)
			}
			input.ProviderId, input.WebIdentityToken = aws.String(provider), aws.String("opaque-fixture-token")
			client, _ := oidcHandlerClient(t, a, now, source)
			out, err := client.AssumeRoleWithWebIdentity(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(out.Provider) != provider || aws.ToString(out.SubjectFromWebIdentityToken) != "subject-web" || a.loaded != 0 {
				t.Fatal("OAuth request used OIDC discovery or returned wrong verified identity")
			}
		})
	}
}

func TestOIDCSDKDerivesProviderScopeFromRole(t *testing.T) {
	for _, scope := range []struct{ partition, region, account string }{
		{"aws", "eu-west-2", "210987654321"},
		{"aws-cn", "cn-north-1", "123456789012"},
		{"aws-us-gov", "us-gov-west-1", "123456789012"},
	} {
		t.Run(scope.partition+scope.account, func(t *testing.T) {
			a, input, now := oidcHandlerFixture(t, "algorithm-RS256")
			old := "arn:aws:iam::123456789012:"
			prefix := "arn:" + scope.partition + ":iam::" + scope.account + ":"
			a.provider.ARN = strings.Replace(a.provider.ARN, old, prefix, 1)
			a.role.ARN = strings.Replace(a.role.ARN, old, prefix, 1)
			a.role.TrustPolicy = strings.ReplaceAll(a.role.TrustPolicy, old, prefix)
			input.RoleArn = aws.String(a.role.ARN)
			client, server := oidcHandlerClient(t, a, now, nil)
			out, err := client.AssumeRoleWithWebIdentity(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(out.Provider) != a.provider.ARN || a.metadata.AccountID != scope.account || a.metadata.Partition != scope.partition {
				t.Fatal("provider was looked up outside the requested role scope")
			}
			signed := sdksts.New(sdksts.Options{Region: scope.region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(aws.ToString(out.Credentials.AccessKeyId), aws.ToString(out.Credentials.SecretAccessKey), aws.ToString(out.Credentials.SessionToken)), Retryer: aws.NopRetryer{}})
			who, err := signed.GetCallerIdentity(context.Background(), &sdksts.GetCallerIdentityInput{})
			if err != nil || aws.ToString(who.Account) != scope.account || !strings.HasPrefix(aws.ToString(who.Arn), "arn:"+scope.partition+":sts::"+scope.account+":") {
				t.Fatalf("wrong issued scope: %v %+v", err, who)
			}
		})
	}
}
