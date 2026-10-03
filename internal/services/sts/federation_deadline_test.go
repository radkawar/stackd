package sts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

// The channels model waiting for IAM's transaction lock after authentication.
// Its callback captures the current instant only after the lock is acquired.
type deadlineAuthority struct {
	role             RoleSnapshot
	source           *clock.Manual
	store            *identity.Store
	repository       identity.Repository
	entered, release chan struct{}
}

func (a *deadlineAuthority) WithFederationSession(ctx context.Context, _ FederationProviderReference, _ string, fn func(context.Context, RoleSnapshot, FederatedCredentialIssuer) error) error {
	close(a.entered)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-a.release:
	}
	now := a.source.Now()
	role := a.role
	role.EvaluationTime = &now
	return fn(ctx, role, a.store.WithRepositoryAt(a.repository, now))
}

func deadlineSDKClient(t *testing.T, dependencies Dependencies, role RoleSnapshot, source *clock.Manual) (*sdksts.Client, *deadlineAuthority) {
	t.Helper()
	repository := identity.NewMemoryRepository()
	store := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: repository, Clock: source})
	authority := &deadlineAuthority{role: role, source: source, store: store, repository: repository, entered: make(chan struct{}), release: make(chan struct{})}
	dependencies.Federation, dependencies.Credentials, dependencies.Clock = authority, store, source
	s := NewWithDependencies(dependencies)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata := awsctx.Metadata{Region: "us-east-1", Partition: "aws", RequestID: "federation-deadline"}
		s.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), metadata)))
	}))
	t.Cleanup(server.Close)
	return sdksts.New(sdksts.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: aws.AnonymousCredentials{}, Retryer: aws.NopRetryer{}}), authority
}

func advanceBlockedAuthority(t *testing.T, ctx context.Context, authority *deadlineAuthority, target time.Time) {
	t.Helper()
	select {
	case <-ctx.Done():
		t.Fatal("request did not reach federation authority", ctx.Err())
	case <-authority.entered:
	}
	if err := authority.source.Advance(target.Sub(authority.source.Now())); err != nil {
		t.Fatal(err)
	}
	close(authority.release)
}

func checkDeadlineCredentials(t *testing.T, authority *deadlineAuthority, credentials *ststypes.Credentials, err error, atDeadline bool, code string, duration time.Duration) {
	t.Helper()
	if atDeadline {
		oidcHandlerError(t, err, code)
		if credentials != nil {
			t.Fatal("expired token returned credentials")
		}
		if err := authority.repository.View(t.Context(), func(reader identity.Reader) error {
			records, err := reader.FindPrincipal("123456789012", authority.role.ID)
			if len(records) != 0 {
				t.Fatal("expired token persisted a role session")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err != nil || credentials == nil {
		t.Fatal("token expired before its exclusive authentication deadline", err)
	}
	if !aws.ToTime(credentials.Expiration).Equal(authority.source.Now().Add(duration)) {
		t.Fatal("authentication expiry unexpectedly capped credential lifetime")
	}
}

func TestFederationDeadlineOIDCWhileAuthorityBlocked(t *testing.T) {
	for _, atDeadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("at-deadline=%t", atDeadline), func(t *testing.T) {
			a, input, now := oidcHandlerFixture(t, "algorithm-RS256")
			input.DurationSeconds = aws.Int32(7200)
			token, apiErr := parseOIDCJWT(aws.ToString(input.WebIdentityToken))
			if apiErr != nil {
				t.Fatal(apiErr)
			}
			expiry, err := oidcTimestamp(token.Claims["exp"])
			if err != nil {
				t.Fatal(err)
			}
			deadline := expiry.Add(5 * time.Minute)
			target := deadline
			if !atDeadline {
				target = target.Add(-time.Nanosecond)
			}
			client, authority := deadlineSDKClient(t, Dependencies{OIDCProviders: a, Roles: a}, a.role, clock.NewManual(now))
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var out *sdksts.AssumeRoleWithWebIdentityOutput
			done := make(chan struct{})
			go func() { defer close(done); out, err = client.AssumeRoleWithWebIdentity(ctx, input) }()
			advanceBlockedAuthority(t, ctx, authority, target)
			<-done
			var credentials *ststypes.Credentials
			if out != nil {
				credentials = out.Credentials
			}
			checkDeadlineCredentials(t, authority, credentials, err, atDeadline, "ExpiredTokenException", 2*time.Hour)
		})
	}
}

func TestFederationDeadlineSAMLWhileAuthorityBlocked(t *testing.T) {
	f := newSAMLTestFixture(t)
	for _, earliest := range []string{"subject", "conditions", "no-conditions-expiry"} {
		for _, atDeadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/at-deadline=%t", earliest, atDeadline), func(t *testing.T) {
				assertion := f.assertion()
				conditions, _ := samlOne(assertion, samlAssertionNS, "Conditions")
				subject, _ := samlOne(assertion, samlAssertionNS, "Subject")
				confirmation, _ := samlOne(subject, samlAssertionNS, "SubjectConfirmation")
				data, _ := samlOne(confirmation, samlAssertionNS, "SubjectConfirmationData")
				deadline := f.now.Add(time.Minute)
				if earliest == "conditions" {
					conditions.CreateAttr("NotOnOrAfter", deadline.Format(time.RFC3339Nano))
				} else {
					data.CreateAttr("NotOnOrAfter", deadline.Format(time.RFC3339Nano))
					if earliest == "no-conditions-expiry" {
						conditions.RemoveAttr("NotOnOrAfter")
					}
				}
				input := &sdksts.AssumeRoleWithSAMLInput{RoleArn: aws.String(f.roleARN), PrincipalArn: aws.String(f.provider.ARN), SAMLAssertion: aws.String(base64.StdEncoding.EncodeToString(samlTestBytes(t, f.response(f.sign(t, assertion)))))}
				role := RoleSnapshot{ARN: f.roleARN, ID: "AROATESTDEADLINE", Name: "saml-test", MaxSessionDuration: time.Hour, TrustPolicy: fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithSAML"}}`, f.provider.ARN)}
				providers := &samlHandlerAuthority{provider: f.provider, role: role}
				client, authority := deadlineSDKClient(t, Dependencies{SAMLProviders: providers, Roles: providers}, role, clock.NewManual(f.now))
				target := deadline
				if !atDeadline {
					target = target.Add(-time.Nanosecond)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				var out *sdksts.AssumeRoleWithSAMLOutput
				var err error
				done := make(chan struct{})
				go func() { defer close(done); out, err = client.AssumeRoleWithSAML(ctx, input) }()
				advanceBlockedAuthority(t, ctx, authority, target)
				<-done
				var credentials *ststypes.Credentials
				if out != nil {
					credentials = out.Credentials
				}
				checkDeadlineCredentials(t, authority, credentials, err, atDeadline, "ExpiredTokenException", time.Hour)
			})
		}
	}
}

type deadlineOAuthSource struct {
	httpOAuthTokens
	response map[string]json.RawMessage
}

func (s deadlineOAuthSource) VerifyOAuthAccessToken(_ context.Context, provider, _ string) (OAuthIdentity, error) {
	if provider == "www.amazon.com" {
		return s.amazonIdentity(s.response)
	}
	return s.facebookIdentity(s.response)
}

func TestFederationDeadlineOAuthWhileAuthorityBlocked(t *testing.T) {
	now := time.Date(2035, 2, 3, 4, 5, 6, 0, time.UTC)
	for _, provider := range []string{"www.amazon.com", "graph.facebook.com"} {
		for _, atDeadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/at-deadline=%t", provider, atDeadline), func(t *testing.T) {
				source := clock.NewManual(now)
				deadline := now.Add(time.Minute)
				response := `{"iss":"https://www.amazon.com","user_id":"caller","aud":"app","app_id":"app","exp":60}`
				if provider == "graph.facebook.com" {
					response = fmt.Sprintf(`{"data":{"is_valid":true,"user_id":"caller","app_id":"app","expires_at":%d,"data_access_expires_at":%d}}`, now.Add(time.Hour).Unix(), deadline.Unix())
				}
				oauth := deadlineOAuthSource{httpOAuthTokens: httpOAuthTokens{now: source.Now}}
				if err := json.Unmarshal([]byte(response), &oauth.response); err != nil {
					t.Fatal(err)
				}
				role := RoleSnapshot{ARN: "arn:aws:iam::123456789012:role/oauth", ID: "AROADEADLINE", Name: "oauth", MaxSessionDuration: time.Hour, TrustPolicy: fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity"}}`, provider)}
				client, authority := deadlineSDKClient(t, Dependencies{OAuthTokens: oauth}, role, source)
				input := &sdksts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String(role.ARN), RoleSessionName: aws.String("deadline-session"), ProviderId: aws.String(provider), WebIdentityToken: aws.String("opaque-provider-token")}
				target := deadline
				if !atDeadline {
					target = target.Add(-time.Nanosecond)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				var out *sdksts.AssumeRoleWithWebIdentityOutput
				var err error
				done := make(chan struct{})
				go func() { defer close(done); out, err = client.AssumeRoleWithWebIdentity(ctx, input) }()
				advanceBlockedAuthority(t, ctx, authority, target)
				<-done
				var credentials *ststypes.Credentials
				if out != nil {
					credentials = out.Credentials
				}
				checkDeadlineCredentials(t, authority, credentials, err, atDeadline, "IDPRejectedClaim", time.Hour)
			})
		}
	}
}
