package stackd_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	idptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd"
	"stackd/storage"
)

// This is an operator-owned HTTPS OpenID provider, not an unsigned identity
// injection. The rooted broker must fetch its JWKS and validate its JWT before
// invoking real customer Python through the native Lambda Runtime API.
func TestCognitoInboundFederationNativeLambda(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise real native federation")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			var upstream *httptest.Server
			var mu sync.Mutex
			var nonce, upstreamPKCE, upstreamRedirect string
			var forged bool
			upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					json.NewEncoder(w).Encode(map[string]string{"issuer": "https://accounts.google.com", "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"})
				case "/jwks":
					json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "native-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(signingKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signingKey.E)).Bytes())}}})
				case "/token":
					if r.ParseForm() != nil {
						http.Error(w, "invalid form", 400)
						return
					}
					mu.Lock()
					n, p, redirect, bad := nonce, upstreamPKCE, upstreamRedirect, forged
					mu.Unlock()
					verifierHash := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
					if r.PostForm.Get("client_id") != "operator-client" || r.PostForm.Get("client_secret") != "operator-secret" || r.PostForm.Get("code") != "upstream-code" || r.PostForm.Get("redirect_uri") != redirect || base64.RawURLEncoding.EncodeToString(verifierHash[:]) != p {
						http.Error(w, "invalid exchange", 400)
						return
					}
					now := time.Now()
					header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "native-key"})
					body, _ := json.Marshal(map[string]any{"iss": "https://accounts.google.com", "aud": "operator-client", "sub": "native-subject", "nonce": n, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "email": "native@example.invalid", "email_verified": true})
					input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
					digest := sha256.Sum256([]byte(input))
					signature, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, digest[:])
					if err != nil {
						http.Error(w, "signing error", 500)
						return
					}
					if bad {
						signature[0] ^= 1
					}
					json.NewEncoder(w).Encode(map[string]any{"access_token": "operator-access", "token_type": "Bearer", "id_token": input + "." + base64.RawURLEncoding.EncodeToString(signature), "expires_in": 3600})
				case "/userinfo":
					if r.Header.Get("Authorization") != "Bearer operator-access" {
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					json.NewEncoder(w).Encode(map[string]string{"sub": "native-subject", "given_name": "BeforePython"})
				default:
					http.NotFound(w, r)
				}
			}))
			defer upstream.Close()
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "inbound.sqlite"))
			}
			_, server := newLambdaDockerStack(t, stackd.Config{Storage: backends, AccountID: cognitoGuardAccount, OutboundHTTP: nativeGoogleHTTPClient(upstream)}, nil)
			clients := cloudClients{server}
			idp := cognitoWorkflowClient(clients, "us-east-1", cognitoGuardAccount, "test")
			functions := lambda.New(lambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			role, err := clients.iam("test", "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("native-inbound-role"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			source := `def handler(event, context):
    assert event['version'] == '1'
    assert event['triggerSource'] == 'InboundFederation_ExternalProvider'
    assert event['request']['providerName'] == 'Google'
    assert event['request']['attributes']['idToken']['sub'] == 'native-subject'
    assert event['request']['attributes']['userInfo']['given_name'] == 'BeforePython'
    assert event['request']['attributes']['tokenResponse']['access_token'] == 'operator-access'
    event['response']['userAttributesToMap'] = {'email': 'native@example.invalid', 'email_verified': 'true', 'given_name': 'AfterNativePython'}
    return event
`
			function, err := functions.CreateFunction(t.Context(), &lambda.CreateFunctionInput{FunctionName: aws.String("native-inbound-hook"), Role: role.Role.Arn, Runtime: lambdatypes.RuntimePython312, Handler: aws.String("handler.handler"), Architectures: []lambdatypes.Architecture{lambdatypes.ArchitectureX8664}, Timeout: aws.Int32(5), Code: &lambdatypes.FunctionCode{ZipFile: lambdaZIP(t, map[string]string{"handler.py": source})}})
			if err != nil {
				t.Fatal(err)
			}
			if err := lambda.NewFunctionActiveWaiter(functions, fastLambdaActiveWaiter).Wait(t.Context(), &lambda.GetFunctionConfigurationInput{FunctionName: function.FunctionName}, time.Minute); err != nil {
				t.Fatal(err)
			}
			pool, err := idp.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("native-inbound"), UsernameAttributes: []idptypes.UsernameAttributeType{idptypes.UsernameAttributeTypeEmail}, UserPoolTier: idptypes.UserPoolTierTypeEssentials, LambdaConfig: &idptypes.LambdaConfigType{InboundFederation: &idptypes.InboundFederationLambdaType{LambdaArn: function.FunctionArn, LambdaVersion: idptypes.InboundFederationLambdaVersionTypeV10}}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = idp.CreateUserPoolDomain(t.Context(), &cognitoidentityprovider.CreateUserPoolDomainInput{UserPoolId: pool.UserPool.Id, Domain: aws.String("native-inbound")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = idp.CreateIdentityProvider(t.Context(), &cognitoidentityprovider.CreateIdentityProviderInput{UserPoolId: pool.UserPool.Id, ProviderName: aws.String("Google"), ProviderType: idptypes.IdentityProviderTypeTypeGoogle, ProviderDetails: map[string]string{"client_id": "operator-client", "client_secret": "operator-secret", "authorize_scopes": "openid email profile"}, AttributeMapping: map[string]string{"email": "email", "email_verified": "email_verified", "given_name": "given_name"}})
			if err != nil {
				t.Fatal(err)
			}
			callback := "https://app.example.invalid/callback"
			client, err := idp.CreateUserPoolClient(t.Context(), &cognitoidentityprovider.CreateUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientName: aws.String("native-oauth"), GenerateSecret: true, AllowedOAuthFlowsUserPoolClient: true, AllowedOAuthFlows: []idptypes.OAuthFlowType{idptypes.OAuthFlowTypeCode}, AllowedOAuthScopes: []string{"openid", "email", "profile", "aws.cognito.signin.user.admin"}, CallbackURLs: []string{callback}, SupportedIdentityProviders: []string{"Google"}})
			if err != nil {
				t.Fatal(err)
			}
			browser := &http.Client{Transport: server.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 30 * time.Second}
			verifier := strings.Repeat("v", 43)
			sum := sha256.Sum256([]byte(verifier))
			authorize := func() string {
				t.Helper()
				query := url.Values{"client_id": {aws.ToString(client.UserPoolClient.ClientId)}, "response_type": {"code"}, "redirect_uri": {callback}, "identity_provider": {"Google"}, "scope": {"openid email profile aws.cognito.signin.user.admin"}, "state": {"browser-state"}, "nonce": {"application-nonce"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
				response, err := browser.Get(server.URL + "/oauth2/authorize?" + query.Encode())
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				location, err := url.Parse(response.Header.Get("Location"))
				if err != nil || location.Host == "" {
					t.Fatalf("authorize status=%d location=%s err=%v", response.StatusCode, response.Header.Get("Location"), err)
				}
				mu.Lock()
				nonce = location.Query().Get("nonce")
				upstreamPKCE = location.Query().Get("code_challenge")
				upstreamRedirect = location.Query().Get("redirect_uri")
				mu.Unlock()
				return location.Query().Get("state")
			}
			finish := func(state string) *url.URL {
				t.Helper()
				response, err := browser.Get(server.URL + "/oauth2/idpresponse?" + url.Values{"state": {state}, "code": {"upstream-code"}}.Encode())
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, _ := io.ReadAll(response.Body)
				location, err := url.Parse(response.Header.Get("Location"))
				if err != nil || location.Host == "" {
					t.Fatalf("callback status=%d body=%s location=%q err=%v", response.StatusCode, body, response.Header.Get("Location"), err)
				}
				return location
			}
			// Cryptographically forged identity must not even create a federated user.
			mu.Lock()
			forged = true
			mu.Unlock()
			bad := finish(authorize())
			if bad.Query().Get("error") == "" {
				t.Fatal("forged JWT trusted")
			}
			_, err = idp.AdminGetUser(t.Context(), &cognitoidentityprovider.AdminGetUserInput{UserPoolId: pool.UserPool.Id, Username: aws.String("Google_native-subject")})
			assertAPIError(t, err, "UserNotFoundException")
			mu.Lock()
			forged = false
			mu.Unlock()
			// Real policy authority is required even when the upstream identity is valid.
			denied := finish(authorize())
			if denied.Query().Get("error") == "" {
				t.Fatal("missing Lambda permission bypassed")
			}
			_, err = functions.AddPermission(t.Context(), &lambda.AddPermissionInput{FunctionName: function.FunctionArn, StatementId: aws.String("cognito-inbound-pool"), Action: aws.String("lambda:InvokeFunction"), Principal: aws.String("cognito-idp.amazonaws.com"), SourceArn: pool.UserPool.Arn, SourceAccount: aws.String(cognitoGuardAccount)})
			if err != nil {
				t.Fatal(err)
			}
			redirected := finish(authorize())
			code := redirected.Query().Get("code")
			if code == "" || redirected.Query().Get("state") != "browser-state" {
				t.Fatalf("callback=%s", redirected)
			}
			redeem := func() (int, map[string]any) {
				t.Helper()
				form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback}, "code_verifier": {verifier}}
				request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/oauth2/token", strings.NewReader(form.Encode()))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.SetBasicAuth(aws.ToString(client.UserPoolClient.ClientId), aws.ToString(client.UserPoolClient.ClientSecret))
				response, err := browser.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				var result map[string]any
				if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
					t.Fatal(err)
				}
				return response.StatusCode, result
			}
			status, tokens := redeem()
			if status != 200 {
				t.Fatalf("token status=%d body=%v", status, tokens)
			}
			idToken, _ := tokens["id_token"].(string)
			parts := strings.Split(idToken, ".")
			if len(parts) != 3 {
				t.Fatalf("no ID token: %v", tokens)
			}
			claimsBody, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatal(err)
			}
			var claims map[string]any
			if err := json.Unmarshal(claimsBody, &claims); err != nil {
				t.Fatal(err)
			}
			if claims["given_name"] != "AfterNativePython" || claims["nonce"] != "application-nonce" || claims["at_hash"] == nil {
				t.Fatalf("native mapping not issued: %v", claims)
			}
			stored, err := idp.AdminGetUser(t.Context(), &cognitoidentityprovider.AdminGetUserInput{UserPoolId: pool.UserPool.Id, Username: aws.String("Google_native-subject")})
			if err != nil || stored.UserStatus != idptypes.UserStatusTypeExternalProvider {
				t.Fatalf("federated user=%v err=%v", stored, err)
			}
			attributes := map[string]string{}
			for _, a := range stored.UserAttributes {
				attributes[aws.ToString(a.Name)] = aws.ToString(a.Value)
			}
			if attributes["given_name"] != "AfterNativePython" {
				t.Fatalf("native mapping not persisted: %v", attributes)
			}
			if status, replay := redeem(); status == 200 || replay["error"] != "invalid_grant" {
				t.Fatalf("code replay accepted: %d %v", status, replay)
			}
			_, err = functions.RemovePermission(t.Context(), &lambda.RemovePermissionInput{FunctionName: function.FunctionArn, StatementId: aws.String("cognito-inbound-pool")})
			if err != nil {
				t.Fatal(err)
			}
			revoked := finish(authorize())
			if revoked.Query().Get("error") == "" {
				t.Fatal("revoked Lambda permission bypassed")
			}
		})
	}
}

type nativeGoogleTransport func(*http.Request) (*http.Response, error)

func (f nativeGoogleTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func nativeGoogleHTTPClient(upstream *httptest.Server) *http.Client {
	paths := map[string]string{
		"accounts.google.com/.well-known/openid-configuration": "/.well-known/openid-configuration",
		"oauth2.googleapis.com/token":                          "/token",
		"openidconnect.googleapis.com/v1/userinfo":             "/userinfo",
		"www.googleapis.com/oauth2/v3/certs":                   "/jwks",
	}
	target, _ := url.Parse(upstream.URL)
	return &http.Client{Transport: nativeGoogleTransport(func(r *http.Request) (*http.Response, error) {
		path, ok := paths[r.URL.Host+r.URL.Path]
		if r.URL.Scheme != "https" || !ok {
			return nil, fmt.Errorf("unexpected canonical Google destination: %s", r.URL)
		}
		forwarded := r.Clone(r.Context())
		u := *r.URL
		u.Scheme, u.Host, u.Path = target.Scheme, target.Host, path
		forwarded.URL, forwarded.Host = &u, target.Host
		return upstream.Client().Transport.RoundTrip(forwarded)
	})}
}
