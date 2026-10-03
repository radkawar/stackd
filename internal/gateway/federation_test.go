package gateway_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	stsclient "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"stackd/internal/awsapi"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/gateway"
	"stackd/internal/identity"
	"stackd/internal/services/sts"
)

type federationRouteProvider struct {
	calls    int
	action   string
	metadata awsctx.Metadata
	decoded  bool
}

func (*federationRouteProvider) Operations() []string {
	return []string{"AssumeRoleWithWebIdentity", "AssumeRoleWithSAML", "GetCallerIdentity"}
}
func (p *federationRouteProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.calls++
	p.action = r.Form.Get("Action")
	p.metadata = awsctx.FromContext(r.Context())
	_, p.decoded = awsapi.FromContext(r.Context())
	// A routing test must stop at token verification, never issue mock credentials.
	awswire.QueryError(w, r, sts.Namespace, &awswire.Error{Code: "InvalidIdentityToken", Message: "Token reached verifier.", StatusCode: 400})
}

type rejectingFederationCredentials struct{}

func bodyReader(value string) io.ReadCloser { return io.NopCloser(strings.NewReader(value)) }

func (rejectingFederationCredentials) Resolve(context.Context, string) (identity.Credential, error) {
	return identity.Credential{}, errors.New("unsigned federation must not resolve AWS credentials")
}

func federationGateway(t *testing.T, provider *federationRouteProvider, limit int64) *gateway.Gateway {
	return configuredFederationGateway(t, provider, gateway.Config{Credentials: rejectingFederationCredentials{}, MaxBodyBytes: limit})
}

func configuredFederationGateway(t *testing.T, provider *federationRouteProvider, config gateway.Config) *gateway.Gateway {
	t.Helper()
	registry := &gateway.Registry{}
	model, _ := awscatalog.LookupService("sts")
	if err := registry.Register(gateway.Service{Name: "sts", SigningName: "sts", Protocol: gateway.Query, QueryVersion: "2011-06-15", Namespace: sts.Namespace, Provider: provider, Model: &model, Decode: stsapi.DecodeRequest}); err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(registry, config)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func federationParams(action string) url.Values {
	params := url.Values{"Action": {action}, "Version": {"2011-06-15"}, "RoleArn": {"arn:aws:iam::123456789012:role/web"}}
	if action == "AssumeRoleWithSAML" {
		params.Set("PrincipalArn", "arn:aws:iam::123456789012:saml-provider/example")
		params.Set("SAMLAssertion", "dGVzdA==")
	} else {
		params.Set("RoleSessionName", "route-session")
		params.Set("WebIdentityToken", "token-for-routing")
	}
	return params
}

func TestSDKUnsignedFederationRouting(t *testing.T) {
	for _, action := range []string{"AssumeRoleWithWebIdentity", "AssumeRoleWithSAML"} {
		t.Run(action, func(t *testing.T) {
			provider := &federationRouteProvider{}
			server := httptest.NewServer(federationGateway(t, provider, 0))
			defer server.Close()
			client := stsclient.New(stsclient.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			var err error
			if action == "AssumeRoleWithSAML" {
				_, err = client.AssumeRoleWithSAML(context.Background(), &stsclient.AssumeRoleWithSAMLInput{RoleArn: aws.String("arn:aws:iam::123456789012:role/web"), PrincipalArn: aws.String("arn:aws:iam::123456789012:saml-provider/example"), SAMLAssertion: aws.String("dGVzdA==")})
			} else {
				_, err = client.AssumeRoleWithWebIdentity(context.Background(), &stsclient.AssumeRoleWithWebIdentityInput{RoleArn: aws.String("arn:aws:iam::123456789012:role/web"), RoleSessionName: aws.String("route-session"), WebIdentityToken: aws.String("token-for-routing")})
			}
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "InvalidIdentityToken" {
				t.Fatalf("SDK did not reach token verification: %v", err)
			}
			if provider.calls != 1 || provider.action != action || !provider.decoded || provider.metadata.PrincipalARN != "" || provider.metadata.AccountID != "" || !provider.metadata.TransportKnown {
				t.Fatalf("unexpected anonymous route: %+v", provider)
			}
		})
	}
}

func TestUnsignedFederationRejectsAmbiguousRouting(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*http.Request)
		code string
	}{
		{"other STS action", func(r *http.Request) {
			r.Body = http.NoBody
			r.URL.RawQuery = "Action=GetCallerIdentity&Version=2011-06-15"
		}, "IncompleteSignature"},
		{"other service action", func(r *http.Request) { r.Body = http.NoBody; r.URL.RawQuery = "Action=CreateUser&Version=2010-05-08" }, "IncompleteSignature"},
		{"unimplemented unsigned action", func(r *http.Request) { r.Body = http.NoBody; r.URL.RawQuery = "Action=AssumeRoot&Version=2011-06-15" }, "IncompleteSignature"},
		{"duplicate action", func(r *http.Request) { r.URL.RawQuery = "Action=AssumeRoleWithWebIdentity" }, "InvalidParameterValue"},
		{"conflicting version", func(r *http.Request) { r.URL.RawQuery = "Version=2010-05-08" }, "InvalidParameterValue"},
		{"malformed query", func(r *http.Request) { r.URL.RawQuery = "Action=%ZZ" }, "InvalidParameterValue"},
		{"wrong version", func(r *http.Request) {
			r.Body = http.NoBody
			p := federationParams("AssumeRoleWithWebIdentity")
			p.Set("Version", "2010-05-08")
			r.URL.RawQuery = p.Encode()
		}, "InvalidParameterValue"},
		{"wrong path", func(r *http.Request) { r.URL.Path = "/sts" }, "IncompleteSignature"},
		{"JSON target", func(r *http.Request) { r.Header.Set("X-Amz-Target", "AmazonSQS.AssumeRoleWithWebIdentity") }, "IncompleteSignature"},
		{"empty JSON target", func(r *http.Request) { r.Header.Set("X-Amz-Target", "") }, "IncompleteSignature"},
		{"JSON content type", func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }, "IncompleteSignature"},
		{"multiple content types", func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, "IncompleteSignature"},
		{"unsupported method", func(r *http.Request) { r.Method = http.MethodPut }, "IncompleteSignature"},
		{"empty authorization", func(r *http.Request) { r.Header.Set("Authorization", "") }, "IncompleteSignature"},
		{"malformed authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer untrusted") }, "IncompleteSignature"},
		{"partial header signature", func(r *http.Request) { r.Header.Set("X-Amz-Signature", "partial") }, "IncompleteSignature"},
		{"partial presign", func(r *http.Request) { r.URL.RawQuery = "X-Amz-Algorithm=AWS4-HMAC-SHA256" }, "IncompleteSignature"},
		{"body signature", func(r *http.Request) { r.URL.RawQuery = "Signature=legacy" }, "IncompleteSignature"},
		{"body security token", func(r *http.Request) {
			p := federationParams("AssumeRoleWithWebIdentity")
			p.Set("X-Amz-Security-Token", "partial")
			r.Body = bodyReader(p.Encode())
		}, "IncompleteSignature"},
		{"missing role", func(r *http.Request) {
			p := federationParams("AssumeRoleWithWebIdentity")
			p.Del("RoleArn")
			r.Body = bodyReader(p.Encode())
		}, "ValidationError"},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &federationRouteProvider{}
			g := federationGateway(t, provider, 0)
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(federationParams("AssumeRoleWithWebIdentity").Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			test.edit(r)
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if provider.calls != 0 || w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>"+test.code+"</Code>") {
				t.Fatalf("calls=%d response=%d %s", provider.calls, w.Code, w.Body)
			}
		})
	}
}

func TestUnsignedFederationBoundsAndTrustedMetadata(t *testing.T) {
	provider := &federationRouteProvider{}
	g := federationGateway(t, provider, 64)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(federationParams("AssumeRoleWithWebIdentity").Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 400 || provider.calls != 0 || !strings.Contains(w.Body.String(), "request body too large") {
		t.Fatalf("unbounded body: %d %s", w.Code, w.Body)
	}

	g = federationGateway(t, provider, 0)
	r = httptest.NewRequest(http.MethodGet, "/?"+federationParams("AssumeRoleWithWebIdentity").Encode(), nil)
	r.RemoteAddr = "192.0.2.4:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("X-Forwarded-Proto", "https")
	r = r.WithContext(awsctx.WithMetadata(r.Context(), awsctx.Metadata{AccountID: "123456789012", Partition: "aws", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012", SessionContext: map[string][]string{"issuer:sub": {"spoofed"}}}))
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if provider.calls != 1 || provider.metadata.AccountID != "" || provider.metadata.PrincipalARN != "" || provider.metadata.PrincipalID != "" || len(provider.metadata.SessionContext) != 0 || provider.metadata.SourceIP != "192.0.2.4" || provider.metadata.SecureTransport || !provider.decoded {
		t.Fatalf("untrusted metadata survived: %+v", provider)
	}
}

func TestUnsignedFederationRegionComesFromEndpointConfiguration(t *testing.T) {
	for _, region := range []string{"", "eu-west-2", "cn-north-1", "us-gov-west-1"} {
		t.Run(region, func(t *testing.T) {
			provider := &federationRouteProvider{}
			g := configuredFederationGateway(t, provider, gateway.Config{UnsignedRegion: region})
			params := federationParams("AssumeRoleWithWebIdentity")
			params.Set("Region", "attacker-region-1")
			params.Set("aws:RequestedRegion", "attacker-region-1")
			r := httptest.NewRequest(http.MethodGet, "/?"+params.Encode(), nil)
			r.Header.Set("X-Amz-Region", "attacker-region-1")
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			want := region
			if want == "" {
				want = "us-east-1"
			}
			if provider.calls != 1 || provider.metadata.Region != want {
				t.Fatalf("unsigned region=%q; want %q", provider.metadata.Region, want)
			}
		})
	}
	for _, region := range []string{"US-EAST-1", "us east 1", "us-east-1/iam", "https://sts.example.test", "us-east-0"} {
		if _, err := gateway.New(&gateway.Registry{}, gateway.Config{UnsignedRegion: region}); err == nil {
			t.Fatalf("invalid endpoint region accepted: %s", region)
		}
	}
}
