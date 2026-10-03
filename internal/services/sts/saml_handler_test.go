package sts

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"stackd/clock"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

type samlHandlerAuthority struct {
	provider SAMLProviderSnapshot
	role     RoleSnapshot
	store    *identity.Store
	before   func()
}

func (a *samlHandlerAuthority) SAMLProviderForFederation(_ context.Context, arn string) (SAMLProviderSnapshot, error) {
	if arn != a.provider.ARN {
		return SAMLProviderSnapshot{}, ErrFederationProviderNotFound
	}
	return a.provider, nil
}
func (a *samlHandlerAuthority) RoleForAssumption(_ context.Context, arn string) (RoleSnapshot, error) {
	if arn != a.role.ARN {
		return RoleSnapshot{}, errors.New("role not found")
	}
	return a.role, nil
}
func (*samlHandlerAuthority) ResolveManagedPolicyDocuments(context.Context, []string) ([]string, error) {
	return nil, errors.New("managed policy not found")
}
func (a *samlHandlerAuthority) WithFederationSession(ctx context.Context, ref FederationProviderReference, roleARN string, fn func(context.Context, RoleSnapshot, FederatedCredentialIssuer) error) error {
	if a.before != nil {
		a.before()
	}
	if ref.ARN != a.provider.ARN || ref.ID != a.provider.ID || ref.Version != a.provider.Version {
		return samlInvalid("The provider changed during authentication.")
	}
	if roleARN != a.role.ARN {
		return stsDenied("The role no longer exists.")
	}
	return fn(ctx, a.role, a.store)
}

func newSAMLHandlerClient(t *testing.T, f samlTestFixture) (*sdksts.Client, *samlHandlerAuthority) {
	t.Helper()
	a := &samlHandlerAuthority{provider: f.provider, store: identity.NewStore("123456789012"), role: RoleSnapshot{ARN: f.roleARN, ID: "AROATESTSAML", Name: "saml-test", MaxSessionDuration: 4 * time.Hour}}
	a.role.TrustPolicy = fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":["sts:AssumeRoleWithSAML","sts:TagSession","sts:SetSourceIdentity"],"Condition":{"StringEquals":{"saml:aud":"https://signin.aws.amazon.com/saml"}}}]}`, f.provider.ARN)
	s := NewWithDependencies(Dependencies{Credentials: a.store, Roles: a, SAMLProviders: a, Federation: a, Authorizer: authorization.New(nil, nil), Clock: clock.NewManual(f.now)})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := awsctx.Metadata{Region: "us-east-1", Partition: "aws", RequestID: "saml-sdk-test"}
		s.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), m)))
	}))
	t.Cleanup(server.Close)
	return sdksts.New(sdksts.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: aws.AnonymousCredentials{}, Retryer: aws.NopRetryer{}}), a
}

func samlSDKInput(t *testing.T, f samlTestFixture, scenario string) *sdksts.AssumeRoleWithSAMLInput {
	t.Helper()
	raw, duration := samlAWSScenario(t, f, scenario)
	return &sdksts.AssumeRoleWithSAMLInput{PrincipalArn: aws.String(f.provider.ARN), RoleArn: aws.String(f.roleARN), SAMLAssertion: aws.String(base64.StdEncoding.EncodeToString(raw)), DurationSeconds: duration}
}

func samlSDKError(t *testing.T, err error, code string) {
	t.Helper()
	var api smithy.APIError
	if !errors.As(err, &api) || api.ErrorCode() != code {
		t.Fatalf("error=%v; want %s", err, code)
	}
}

func TestSAMLSDKCredentialsClaimsAndDuration(t *testing.T) {
	f := newSAMLTestFixture(t)
	client, authority := newSAMLHandlerClient(t, f)
	ctx := context.Background()
	for _, scenario := range []string{"assertion_signed", "both_signed", "source_and_tags", "session_duration_900", "session_duration_7200", "api_duration_7200", "session_expires_600", "encrypted_aes128_gcm"} {
		t.Run(scenario, func(t *testing.T) {
			out, err := client.AssumeRoleWithSAML(ctx, samlSDKInput(t, f, scenario))
			if err != nil {
				t.Fatal(err)
			}
			if out.Credentials == nil || out.Credentials.Expiration == nil || !strings.HasPrefix(aws.ToString(out.Credentials.AccessKeyId), "ASIA") || out.AssumedRoleUser == nil {
				t.Fatalf("missing generated output: %+v", out)
			}
			if aws.ToString(out.Subject) != "subject-123" || aws.ToString(out.SubjectType) != "persistent" || aws.ToString(out.Issuer) != f.provider.Issuers[0].EntityID || aws.ToString(out.Audience) != "https://signin.aws.amazon.com/saml" || aws.ToString(out.NameQualifier) == "" {
				t.Fatalf("incorrect assertion output: %+v", out)
			}
			credential, err := authority.store.Resolve(ctx, aws.ToString(out.Credentials.AccessKeyId))
			if err != nil {
				t.Fatal(err)
			}
			if credential.PrincipalID != "AROATESTSAML:saml-session" || credential.IssuerID != "AROATESTSAML" || credential.IssuerARN != f.roleARN || aws.ToString(out.AssumedRoleUser.Arn) != credential.PrincipalARN || credential.SessionToken != aws.ToString(out.Credentials.SessionToken) {
				t.Fatalf("issued identity differs from response: %+v", out.AssumedRoleUser)
			}
			if credential.SessionContext["saml:sub"][0] != "subject-123" || len(credential.SessionContext) != 3 {
				t.Fatalf("incorrect downstream SAML context: %+v", credential.SessionContext)
			}
			if scenario == "source_and_tags" && (credential.SourceIdentity != "source-123" || credential.SessionTags["team"] != "engineering" || len(credential.TransitiveTagKeys) != 1) {
				t.Fatalf("session claims were not persisted")
			}
			want := time.Hour
			switch scenario {
			case "session_duration_900":
				want = 15 * time.Minute
			case "api_duration_7200":
				want = 2 * time.Hour
			case "session_expires_600":
				want = 10 * time.Minute
			}
			got := out.Credentials.Expiration.Sub(f.now)
			if got < want-time.Second || got > want+2*time.Second {
				t.Fatalf("duration=%v; want %v", got, want)
			}
		})
	}
}

func TestSAMLSDKRejectsInvalidAssertionsAndTrust(t *testing.T) {
	f := newSAMLTestFixture(t)
	for _, test := range []struct{ scenario, code string }{
		{"unsigned", "InvalidIdentityToken"}, {"response_signed", "InvalidIdentityToken"}, {"tampered_subject", "InvalidIdentityToken"}, {"expired_conditions", "ExpiredTokenException"}, {"wrong_recipient", "AccessDenied"}, {"wrong_role", "InvalidIdentityToken"},
	} {
		t.Run(test.scenario, func(t *testing.T) {
			client, _ := newSAMLHandlerClient(t, f)
			_, err := client.AssumeRoleWithSAML(context.Background(), samlSDKInput(t, f, test.scenario))
			samlSDKError(t, err, test.code)
			if test.code == "ExpiredTokenException" {
				var modeled *ststypes.ExpiredTokenException
				if !errors.As(err, &modeled) {
					t.Fatalf("expired assertion is not modeled: %v", err)
				}
			}
		})
	}
	for _, kind := range []string{"deleted provider", "recreated provider", "changed provider", "changed trust", "missing TagSession", "missing SetSourceIdentity", "duration exceeds role"} {
		t.Run(kind, func(t *testing.T) {
			client, a := newSAMLHandlerClient(t, f)
			scenario := "assertion_signed"
			code := "AccessDenied"
			switch kind {
			case "deleted provider":
				a.provider.ARN = ""
				code = "InvalidIdentityToken"
			case "recreated provider":
				a.before = func() { a.provider.ID = "SAMLRECREATED" }
				code = "InvalidIdentityToken"
			case "changed provider":
				a.before = func() { a.provider.Version = "changed" }
				code = "InvalidIdentityToken"
			case "changed trust":
				a.before = func() {
					a.role.TrustPolicy = fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithSAML"}]}`, f.provider.ARN)
				}
			case "missing TagSession":
				scenario = "source_and_tags"
				a.role.TrustPolicy = strings.Replace(a.role.TrustPolicy, `,"sts:TagSession"`, "", 1)
			case "missing SetSourceIdentity":
				scenario = "source_and_tags"
				a.role.TrustPolicy = strings.Replace(a.role.TrustPolicy, `,"sts:SetSourceIdentity"`, "", 1)
			case "duration exceeds role":
				scenario = "api_duration_7200"
				a.role.MaxSessionDuration = time.Hour
				code = "ValidationError"
			}
			_, err := client.AssumeRoleWithSAML(context.Background(), samlSDKInput(t, f, scenario))
			samlSDKError(t, err, code)
		})
	}
}

func TestSAMLSDKGlobalTrustContext(t *testing.T) {
	f := newSAMLTestFixture(t)
	for _, test := range []struct {
		name, condition string
		allowed         bool
	}{
		{"provider account", `{"StringEquals":{"aws:PrincipalAccount":"123456789012"}}`, true},
		{"principal type User", `{"StringEquals":{"aws:PrincipalType":"User"}}`, true},
		{"principal type is not SAMLUser", `{"StringEquals":{"aws:PrincipalType":"SAMLUser"}}`, false},
		{"userid is provider ARN", fmt.Sprintf(`{"StringEquals":{"aws:userid":%q}}`, f.provider.ARN), true},
		{"userid excludes subject", fmt.Sprintf(`{"StringEquals":{"aws:userid":%q}}`, f.provider.ARN+":subject-123"), false},
		{"principal ARN absent", `{"Null":{"aws:PrincipalArn":"true"}}`, true},
		{"principal ARN required", `{"Null":{"aws:PrincipalArn":"false"}}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, a := newSAMLHandlerClient(t, f)
			a.role.TrustPolicy = fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithSAML","Condition":%s}]}`, f.provider.ARN, test.condition)
			_, err := client.AssumeRoleWithSAML(context.Background(), samlSDKInput(t, f, "assertion_signed"))
			if test.allowed {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				samlSDKError(t, err, "AccessDenied")
			}
		})
	}
}

func TestSAMLSDKProviderRecreationRetainsARNTrust(t *testing.T) {
	f := newSAMLTestFixture(t)
	client, a := newSAMLHandlerClient(t, f)
	replacement := newSAMLTestFixture(t)
	replacement.provider.ID = "SAMLREPLACEMENT"
	replacement.provider.Version = "version-2"
	a.provider = replacement.provider
	if _, err := client.AssumeRoleWithSAML(context.Background(), samlSDKInput(t, replacement, "assertion_signed")); err != nil {
		t.Fatal(err)
	}
	_, err := client.AssumeRoleWithSAML(context.Background(), samlSDKInput(t, f, "assertion_signed"))
	samlSDKError(t, err, "InvalidIdentityToken")
}
