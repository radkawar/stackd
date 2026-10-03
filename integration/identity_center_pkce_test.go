package stackd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	idptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
)

type pkceSignedClient struct{ client aws.HTTPClient }

func (c pkceSignedClient) Do(request *http.Request) (*http.Response, error) {
	data, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(data))
	sum := sha256.Sum256(data)
	identity := aws.Credentials{AccessKeyID: eventDeliveryAccount, SecretAccessKey: "test"}
	if err = v4.NewSigner().SignHTTP(request.Context(), identity, request, hex.EncodeToString(sum[:]), "sso-oauth", "us-east-1", time.Now()); err != nil {
		return nil, err
	}
	return c.client.Do(request)
}

func TestIdentityCenterPKCEBrowserBindingAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			source := clock.NewManual(time.Now().UTC())
			appID := ""
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				config.SSOUserPoolClientID = appID
				return startPublicCloud(t, config)
			})
			credential := credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", "")
			idp := cognitoidentityprovider.New(cognitoidentityprovider.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credential, HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			pool, err := idp.CreateUserPool(ctx, &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("pkce-login"), UserPoolTier: idptypes.UserPoolTierTypeLite})
			if err != nil {
				t.Fatal(err)
			}
			app, err := idp.CreateUserPoolClient(ctx, &cognitoidentityprovider.CreateUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientName: aws.String("pkce-browser"), ExplicitAuthFlows: []idptypes.ExplicitAuthFlowsType{idptypes.ExplicitAuthFlowsTypeAllowUserPasswordAuth, idptypes.ExplicitAuthFlowsTypeAllowRefreshTokenAuth}})
			if err != nil {
				t.Fatal(err)
			}
			appID = aws.ToString(app.UserPoolClient.ClientId)
			username, password := "alice", "A-local-password-123!"
			if _, err = idp.AdminCreateUser(ctx, &cognitoidentityprovider.AdminCreateUserInput{UserPoolId: pool.UserPool.Id, Username: &username, MessageAction: idptypes.MessageActionTypeSuppress}); err != nil {
				t.Fatal(err)
			}
			if _, err = idp.AdminSetUserPassword(ctx, &cognitoidentityprovider.AdminSetUserPasswordInput{UserPoolId: pool.UserPool.Id, Username: &username, Password: &password, Permanent: true}); err != nil {
				t.Fatal(err)
			}
			admin := identityAdminClient(c, eventDeliveryAccount, "test")
			instance, err := admin.CreateInstance(ctx, &ssoadmin.CreateInstanceInput{Name: aws.String("pkce-instance")})
			if err != nil {
				t.Fatal(err)
			}
			detail, err := admin.DescribeInstance(ctx, &ssoadmin.DescribeInstanceInput{InstanceArn: instance.InstanceArn})
			if err != nil {
				t.Fatal(err)
			}
			directory := identitystore.New(identitystore.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credential, HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			user, err := directory.CreateUser(ctx, &identitystore.CreateUserInput{IdentityStoreId: detail.IdentityStoreId, UserName: &username})
			if err != nil {
				t.Fatal(err)
			}
			permission, err := admin.CreatePermissionSet(ctx, &ssoadmin.CreatePermissionSetInput{InstanceArn: instance.InstanceArn, Name: aws.String("PKCEDeveloper")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = admin.CreateAccountAssignment(ctx, &ssoadmin.CreateAccountAssignmentInput{InstanceArn: instance.InstanceArn, PermissionSetArn: permission.PermissionSet.PermissionSetArn, PrincipalType: "USER", PrincipalId: user.UserId, TargetType: "AWS_ACCOUNT", TargetId: aws.String(eventDeliveryAccount)}); err != nil {
				t.Fatal(err)
			}
			c = reopen()
			oidcClient := func() *ssooidc.Client {
				return ssooidc.New(ssooidc.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credential, HTTPClient: pkceSignedClient{c.server.Client()}, RetryMaxAttempts: 1})
			}
			issuer := "https://identitycenter.amazonaws.com/" + strings.Split(aws.ToString(instance.InstanceArn), "/")[1]
			register := func() *ssooidc.RegisterClientOutput {
				t.Helper()
				v, e := oidcClient().RegisterClient(ctx, &ssooidc.RegisterClientInput{ClientName: aws.String("pkce-test"), ClientType: aws.String("public"), IssuerUrl: &issuer, GrantTypes: []string{"authorization_code", "refresh_token"}, Scopes: []string{"sso:account:access"}, RedirectUris: []string{"http://127.0.0.1/oauth/callback", "https://client.example/callback?kept=a;b", "com.example.client:/oauth/callback", "http://[::1]/oauth/callback"}})
				if e != nil {
					t.Fatal(e)
				}
				return v
			}
			registration, other := register(), register()
			received := make(chan url.Values, 1)
			receive := func() url.Values {
				t.Helper()
				select {
				case v := <-received:
					return v
				default:
					t.Fatal("browser did not reach the registered loopback receiver")
					return nil
				}
			}
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/oauth/callback" {
					http.NotFound(w, r)
					return
				}
				received <- r.URL.Query()
				_, _ = io.WriteString(w, "Authorization received")
			}))
			defer receiver.Close()
			redirect := receiver.URL + "/oauth/callback"
			verifier := strings.Repeat("a", 43)
			sum := sha256.Sum256([]byte(verifier))
			state := "caller state + & = % / 雪"
			authorize := func() url.Values {
				return url.Values{"client_id": {aws.ToString(registration.ClientId)}, "redirect_uri": {redirect}, "response_type": {"code"}, "scopes": {"sso:account:access"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "state": {state}}
			}
			jar, _ := cookiejar.New(nil)
			browser := &http.Client{Jar: jar, Timeout: 10 * time.Second}
			hidden := regexp.MustCompile(`name="(request_id|csrf)" value="([^"]*)"`)
			begin := func(q url.Values) url.Values {
				t.Helper()
				response, e := browser.Get(c.server.URL + "/authorize?" + q.Encode())
				if e != nil {
					t.Fatal(e)
				}
				body, e := io.ReadAll(response.Body)
				response.Body.Close()
				if e != nil {
					t.Fatal(e)
				}
				if response.StatusCode != 200 {
					t.Fatalf("authorize status=%d", response.StatusCode)
				}
				form := url.Values{"username": {username}, "password": {password}, "decision": {"approve"}}
				for _, v := range hidden.FindAllStringSubmatch(string(body), -1) {
					form.Set(v[1], html.UnescapeString(v[2]))
				}
				return form
			}
			post := func(form url.Values, expected int) {
				t.Helper()
				response, e := browser.PostForm(c.server.URL+"/authorize", form)
				if e != nil {
					t.Fatal(e)
				}
				response.Body.Close()
				if response.StatusCode != expected {
					t.Fatalf("login status=%d want=%d", response.StatusCode, expected)
				}
			}
			for _, uri := range []string{"https://client.example/callback?kept=a;b", "com.example.client:/oauth/callback", "http://[::1]:4567/oauth/callback"} {
				q := authorize()
				q.Set("redirect_uri", uri)
				form := begin(q)
				form.Set("decision", "deny")
				noRedirect := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				response, e := noRedirect.PostForm(c.server.URL+"/authorize", form)
				if e != nil {
					t.Fatal(e)
				}
				response.Body.Close()
				location, e := url.Parse(response.Header.Get("Location"))
				if e != nil {
					t.Fatal(e)
				}
				expected, _ := url.Parse(uri)
				if response.StatusCode != http.StatusSeeOther || location.Scheme != expected.Scheme || location.Host != expected.Host || location.Path != expected.Path || location.Query().Get("state") != state || location.Query().Get("error") != "access_denied" || location.Query().Get("kept") != expected.Query().Get("kept") {
					t.Fatal("registered redirect type or existing query was not preserved")
				}
				if expected.RawQuery != "" && !strings.HasPrefix(location.RawQuery, expected.RawQuery+"&") {
					t.Fatalf("registered callback query lost: %q", location.RawQuery)
				}
			}
			// Unknown redirects and unsupported challenges must never open a redirector.
			for _, change := range []struct{ key, value string }{{"redirect_uri", "https://attacker.invalid/callback"}, {"redirect_uri", receiver.URL + "/other"}, {"code_challenge_method", "plain"}, {"client_id", aws.ToString(other.ClientId) + "bad"}, {"scopes", "unknown"}, {"issuer_url", "https://identitycenter.amazonaws.com/ssoins-0000000000000000"}} {
				q := authorize()
				q.Set(change.key, change.value)
				response, e := browser.Get(c.server.URL + "/authorize?" + q.Encode())
				if e != nil {
					t.Fatal(e)
				}
				response.Body.Close()
				if response.StatusCode != 400 || response.Header.Get("Location") != "" {
					t.Fatalf("unsafe authorization accepted for %s", change.key)
				}
			}
			form := begin(authorize())
			originalCSRF := form.Get("csrf")
			form.Set("csrf", "substituted")
			post(form, 403)
			form.Set("csrf", originalCSRF)
			// Pending form and its CSRF state remain usable after backend reconstruction.
			c = reopen()
			post(form, 200)
			callback := receive()
			if callback.Get("state") != state || callback.Get("code") == "" {
				t.Fatal("callback lost code or exact caller state")
			}
			post(form, 400)
			code := callback.Get("code")
			// Authorized, not yet redeemed codes also survive reconstruction.
			c = reopen()
			exchange := func() *ssooidc.CreateTokenInput {
				return &ssooidc.CreateTokenInput{ClientId: registration.ClientId, ClientSecret: registration.ClientSecret, GrantType: aws.String("authorization_code"), Code: &code, CodeVerifier: &verifier, RedirectUri: &redirect}
			}
			for _, change := range []func(*ssooidc.CreateTokenInput){
				func(v *ssooidc.CreateTokenInput) { v.CodeVerifier = aws.String(strings.Repeat("b", 43)) },
				func(v *ssooidc.CreateTokenInput) { v.ClientId = other.ClientId; v.ClientSecret = other.ClientSecret },
				func(v *ssooidc.CreateTokenInput) { v.RedirectUri = aws.String("http://127.0.0.1/oauth/callback") },
			} {
				in := exchange()
				change(in)
				_, e := oidcClient().CreateToken(ctx, in)
				assertAPIError(t, e, "InvalidGrantException")
			}
			type outcome struct {
				token *ssooidc.CreateTokenOutput
				err   error
			}
			outcomes := make(chan outcome, 4)
			for range 4 {
				go func() { token, e := oidcClient().CreateToken(ctx, exchange()); outcomes <- outcome{token, e} }()
			}
			var token *ssooidc.CreateTokenOutput
			for range 4 {
				result := <-outcomes
				if result.err != nil {
					assertAPIError(t, result.err, "InvalidGrantException")
					continue
				}
				if token != nil {
					t.Fatal("concurrent code redemption issued multiple sessions")
				}
				token = result.token
			}
			if token == nil {
				t.Fatal("no concurrent exchange redeemed the authorized code")
			}
			_, err = oidcClient().CreateToken(ctx, exchange())
			assertAPIError(t, err, "InvalidGrantException")
			c = reopen()
			portal := sso.New(sso.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credential, HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			accounts, err := portal.ListAccounts(ctx, &sso.ListAccountsInput{AccessToken: token.AccessToken})
			if err != nil || len(accounts.AccountList) != 1 || aws.ToString(accounts.AccountList[0].AccountId) != eventDeliveryAccount {
				t.Fatalf("portal account authority: %v", err)
			}
			role, err := portal.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{AccessToken: token.AccessToken, AccountId: aws.String(eventDeliveryAccount), RoleName: aws.String("PKCEDeveloper")})
			if err != nil {
				t.Fatal(err)
			}
			actual, err := c.sts(aws.ToString(role.RoleCredentials.AccessKeyId), aws.ToString(role.RoleCredentials.SecretAccessKey), aws.ToString(role.RoleCredentials.SessionToken)).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil || aws.ToString(actual.Account) != eventDeliveryAccount || !strings.Contains(aws.ToString(actual.Arn), "assumed-role/AWSReservedSSO_PKCEDeveloper_") {
				t.Fatalf("issued role identity: %v", err)
			}
			form = begin(authorize())
			post(form, 200)
			code = receive().Get("code")
			source.Advance(5 * time.Minute)
			_, err = oidcClient().CreateToken(ctx, exchange())
			assertAPIError(t, err, "InvalidGrantException")
			form = begin(authorize())
			form.Set("decision", "deny")
			post(form, 200)
			denied := receive()
			if denied.Get("error") != "access_denied" || denied.Get("code") != "" || denied.Get("state") != state {
				t.Fatal("denial did not preserve state without issuing a code")
			}
		})
	}
}

func TestIdentityCenterAuthorizationDoesNotInterceptS3(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			client := s3.New(s3.Options{
				Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), UsePathStyle: true,
				Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", ""),
				HTTPClient:  c.server.Client(), RetryMaxAttempts: 1,
			})
			bucket := aws.String("authorize")
			if _, err := client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: bucket}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.HeadBucket(t.Context(), &s3.HeadBucketInput{Bucket: bucket}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: bucket}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.DeleteBucket(t.Context(), &s3.DeleteBucketInput{Bucket: bucket}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
