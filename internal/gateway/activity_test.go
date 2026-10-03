package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"stackd/internal/awsapi"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

type activityCapture struct {
	metadata        awsctx.Metadata
	service, action string
	calls           int
	err             error
}

func (r *activityCapture) RecordActivity(ctx context.Context, service, action string) error {
	r.metadata, r.service, r.action = awsctx.FromContext(ctx), service, action
	r.calls++
	return r.err
}

type activityProvider struct{ calls int }

func (*activityProvider) Operations() []string { return []string{"Known"} }
func (p *activityProvider) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	p.calls++
	w.WriteHeader(http.StatusNoContent)
}

type activityUsageStore struct {
	*identity.Store
	uses int
}

func (s *activityUsageStore) RecordUsage(ctx context.Context, key, service, region string) error {
	s.uses++
	return s.Store.RecordUsage(ctx, key, service, region)
}

func TestActivityBoundaryAuthenticationAndDecodedOperation(t *testing.T) {
	for _, protocol := range []Protocol{Query, JSON11} {
		t.Run(string(protocol), func(t *testing.T) {
			for _, tc := range []struct {
				name, action, secret  string
				invalid, fail         bool
				wantStatus            int
				wantCalls, wantEffect int
			}{
				{name: "allowed", action: "Known", secret: "test", wantStatus: 204, wantCalls: 1, wantEffect: 1},
				{name: "invalid signature", action: "Known", secret: "wrong", wantStatus: 403},
				{name: "unknown action", action: "Unknown", secret: "test", wantStatus: 400},
				{name: "invalid modeled input", action: "Known", secret: "test", invalid: true, wantStatus: 400, wantCalls: 1},
				{name: "record failure", action: "Known", secret: "test", fail: true, wantStatus: 500, wantCalls: 1},
			} {
				t.Run(tc.name, func(t *testing.T) {
					capture := &activityCapture{}
					if tc.fail {
						capture.err = errors.New("private storage details")
					}
					provider := &activityProvider{}
					store := &activityUsageStore{Store: identity.NewStore("123456789012")}
					registry := &Registry{}
					decode := func(action string, _ awsapi.Request) (awsapi.DecodedRequest, error) {
						if action != "Known" {
							return awsapi.DecodedRequest{}, awsapi.ErrUnknownOperation
						}
						if tc.invalid {
							return awsapi.DecodedRequest{}, &awsapi.ValidationError{}
						}
						return awsapi.DecodedRequest{}, nil
					}
					if err := registry.Register(Service{Name: "canonical-namespace", SigningName: "signing-name", Protocol: protocol, QueryVersion: "2026-01-01", Namespace: "urn:test", TargetPrefix: "Example", Provider: provider, Decode: decode}); err != nil {
						t.Fatal(err)
					}
					g, err := New(registry, Config{Credentials: store, Activity: capture})
					if err != nil {
						t.Fatal(err)
					}
					body := "Action=" + tc.action + "&Version=2026-01-01"
					contentType := "application/x-www-form-urlencoded"
					if protocol == JSON11 {
						body, contentType = `{}`, "application/x-amz-json-1.1"
					}
					r := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader(body))
					r.Header.Set("Content-Type", contentType)
					if protocol == JSON11 {
						r.Header.Set("X-Amz-Target", "Example."+tc.action)
					}
					if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: tc.secret}, r, hashHex([]byte(body)), "signing-name", "eu-west-1", time.Now()); err != nil {
						t.Fatal(err)
					}
					w := httptest.NewRecorder()
					g.ServeHTTP(w, r)
					if w.Code != tc.wantStatus || capture.calls != tc.wantCalls || provider.calls != tc.wantEffect {
						t.Fatalf("status=%d activity=%d effects=%d body=%s", w.Code, capture.calls, provider.calls, w.Body.String())
					}
					if store.uses != 0 {
						t.Fatal("activity recorder and legacy credential recorder both ran")
					}
					if capture.calls > 0 && (capture.service != "canonical-namespace" || capture.action != "Known" || capture.metadata.Region != "eu-west-1" || capture.metadata.PrincipalID != "123456789012" || capture.metadata.AccessKeyID != "test") {
						t.Fatalf("recorded wrong operation or trusted identity: %+v", capture)
					}
					if strings.Contains(w.Body.String(), "private storage") {
						t.Fatal("recording failure exposed storage details")
					}
				})
			}
		})
	}
}

func TestActivityBoundaryCredentialOnlyFallback(t *testing.T) {
	store := &activityUsageStore{Store: identity.NewStore("123456789012")}
	provider := &activityProvider{}
	registry := &Registry{}
	if err := registry.Register(Service{Name: "service", SigningName: "signer", Protocol: Query, QueryVersion: "2026-01-01", Namespace: "urn:test", Provider: provider}); err != nil {
		t.Fatal(err)
	}
	g, err := New(registry, Config{Credentials: store})
	if err != nil {
		t.Fatal(err)
	}
	body := "Action=Known&Version=2026-01-01"
	r := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, r, hashHex([]byte(body)), "signer", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 204 || store.uses != 1 || provider.calls != 1 {
		t.Fatalf("status=%d usage=%d effects=%d", w.Code, store.uses, provider.calls)
	}
}

type unsignedActivityProvider struct{ calls int }

func (*unsignedActivityProvider) Operations() []string { return []string{"AssumeRoleWithSAML"} }
func (p *unsignedActivityProvider) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	p.calls++
	w.WriteHeader(http.StatusNoContent)
}

func TestActivityBoundaryUnsignedFederationHasNoAWSCaller(t *testing.T) {
	capture := &activityCapture{}
	provider := &unsignedActivityProvider{}
	registry := &Registry{}
	if err := registry.Register(Service{Name: "sts", SigningName: "sts", Protocol: Query, QueryVersion: "2011-06-15", Namespace: "urn:sts", Provider: provider}); err != nil {
		t.Fatal(err)
	}
	g, err := New(registry, Config{Activity: capture})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader("Action=AssumeRoleWithSAML&Version=2011-06-15"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 204 || capture.calls != 0 || provider.calls != 1 {
		t.Fatalf("status=%d activity=%d effects=%d", w.Code, capture.calls, provider.calls)
	}
}
