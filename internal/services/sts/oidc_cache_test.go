package sts

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/jwt"
)

type oidcTestSource struct {
	mu       sync.Mutex
	provider OIDCProviderSnapshot
	keys     OIDCKeySet
	calls    atomic.Int32
	load     func(context.Context) error
}

func (s *oidcTestSource) OIDCProviderForFederation(context.Context, string) (OIDCProviderSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.provider
	p.ClientIDs = append([]string(nil), p.ClientIDs...)
	p.Thumbprints = append([]string(nil), p.Thumbprints...)
	return p, nil
}
func (s *oidcTestSource) ResolveOIDCSigningKeys(ctx context.Context, _ string) (OIDCKeySet, error) {
	s.calls.Add(1)
	if s.load != nil {
		if err := s.load(ctx); err != nil {
			return OIDCKeySet{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneOIDCKeySet(s.keys), nil
}
func oidcCacheFixture(t *testing.T) (*oidcTestSource, jwt.Token, time.Time) {
	t.Helper()
	data, err := os.ReadFile("testdata/oidc/aws-initial.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Issuer    string
		Scenarios []struct {
			ExitCode   int    `json:"exit_code"`
			ObservedAt string `json:"observed_at"`
			Input      struct{ WebIdentityToken string }
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Scenarios {
		if row.ExitCode != 0 {
			continue
		}
		now, err := time.Parse(time.RFC3339Nano, row.ObservedAt)
		if err != nil {
			t.Fatal(err)
		}
		token, apiErr := parseOIDCJWT(row.Input.WebIdentityToken)
		if apiErr != nil {
			t.Fatal(apiErr)
		}
		provider := OIDCProviderSnapshot{ARN: "arn:aws:iam::123456789012:oidc-provider/" + strings.TrimPrefix(fixture.Issuer, "https://"), ID: "provider", Version: "1", IssuerURL: fixture.Issuer, ClientIDs: []string{"client-a", "client-b"}}
		return &oidcTestSource{provider: provider, keys: OIDCKeySet{IssuerURL: fixture.Issuer, ProviderID: provider.ID, ProviderVersion: provider.Version, Keys: oidcFixtureKeys(t), CacheUntil: now.Add(time.Hour)}}, token, now
	}
	t.Fatal("no successful AWS fixture")
	return nil, jwt.Token{}, time.Time{}
}

func TestOIDCKeyRotationRefreshAndProviderChange(t *testing.T) {
	source, token, now := oidcCacheFixture(t)
	correct := cloneOIDCKeySet(source.keys)
	old, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	source.keys.Keys[0].N = base64.RawURLEncoding.EncodeToString(old.N.Bytes())
	service := &Service{oidcProviders: source, now: func() time.Time { return now }}
	if _, _, err := service.oidcKeys.resolve(context.Background(), source, source.provider, now, false); err != nil {
		t.Fatal(err)
	}
	source.keys = correct
	verified, apiErr := service.verifyConfiguredOIDC(context.Background(), token, source.provider)
	if apiErr != nil || verified.subject != "subject-probe" || source.calls.Load() != 2 {
		t.Fatalf("rotation=%+v %v calls=%d", verified, apiErr, source.calls.Load())
	}
	source.load = func(context.Context) error {
		source.mu.Lock()
		source.provider.Version = "changed"
		source.mu.Unlock()
		return nil
	}
	service.oidcKeys = oidcKeyCache{}
	if _, apiErr := service.verifyConfiguredOIDC(context.Background(), token, OIDCProviderSnapshot{ARN: source.provider.ARN, ID: source.provider.ID, Version: "1", IssuerURL: source.provider.IssuerURL, ClientIDs: source.provider.ClientIDs}); apiErr == nil {
		t.Fatal("provider mutation during verification accepted")
	}
}

func TestOIDCKeySetChangesReturnModeledTokenError(t *testing.T) {
	for _, changed := range []string{"id", "version", "issuer"} {
		t.Run(changed, func(t *testing.T) {
			source, token, now := oidcCacheFixture(t)
			switch changed {
			case "id":
				source.keys.ProviderID = "recreated"
			case "version":
				source.keys.ProviderVersion = "changed"
			case "issuer":
				source.keys.IssuerURL = "https://another.example.test"
			}
			service := &Service{oidcProviders: source, now: func() time.Time { return now }}
			_, apiErr := service.verifyConfiguredOIDC(context.Background(), token, source.provider)
			if apiErr == nil || apiErr.Code != "InvalidIdentityToken" {
				t.Fatalf("changed key set: %v", apiErr)
			}
			_, _, err := service.oidcKeys.resolve(context.Background(), source, source.provider, now, false)
			var modeled *awswire.Error
			if !errors.As(err, &modeled) || modeled.Code != "InvalidIdentityToken" {
				t.Fatalf("cache mismatch was not a modeled error: %v", err)
			}
		})
	}
}

func TestOIDCKeyCacheConcurrencyCancellationAndCopies(t *testing.T) {
	source, _, now := oidcCacheFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	source.load = func(ctx context.Context) error {
		close(entered)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return nil
		}
	}
	cache := &oidcKeyCache{}
	done := make(chan error, 1)
	go func() {
		_, _, err := cache.resolve(context.Background(), source, source.provider, now, false)
		done <- err
	}()
	<-entered
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := cache.resolve(canceled, source, source.provider, now, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cache wait=%v", err)
	}
	var group sync.WaitGroup
	failures := make(chan error, 20)
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			keys, _, err := cache.resolve(context.Background(), source, source.provider, now, false)
			if err != nil {
				failures <- err
				return
			}
			keys.Keys[0].N = "caller mutation"
		}()
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if source.calls.Load() != 1 {
		t.Fatalf("duplicate discovery requests=%d", source.calls.Load())
	}
	keys, cached, err := cache.resolve(context.Background(), source, source.provider, now, false)
	if err != nil || !cached || keys.Keys[0].N == "caller mutation" {
		t.Fatalf("detached cache=%+v %v %v", keys, cached, err)
	}
	source.load = nil
	source.keys.CacheUntil = now.Add(2 * time.Hour)
	if _, cached, err := cache.resolve(context.Background(), source, source.provider, now.Add(time.Hour), false); err != nil || cached {
		t.Fatalf("expiry did not refresh %v %v", cached, err)
	}
	if source.calls.Load() != 2 {
		t.Fatal("expired key set reused")
	}
}

func TestOIDCIssuerProviderScope(t *testing.T) {
	for _, test := range []struct{ issuer, want string }{
		{"https://Issuer.example.com:443/path/", "arn:aws-cn:iam::123456789012:oidc-provider/Issuer.example.com/path/"},
		{"accounts.google.com", "accounts.google.com"},
		{"https://accounts.google.com", "accounts.google.com"},
		{"https://cognito-identity.amazonaws.com", "cognito-identity.amazonaws.com"},
	} {
		actual, apiErr := oidcIssuerPrincipal(test.issuer, "aws-cn", "123456789012")
		if apiErr != nil || actual != test.want {
			t.Fatalf("issuer %q=%q %v", test.issuer, actual, apiErr)
		}
	}
	for _, issuer := range []string{"http://issuer.example.com", "https://user@issuer.example.com", "https://issuer.example.com/?query=x", "https://issuer.example.com:8443", "https:///missing"} {
		if _, apiErr := oidcIssuerPrincipal(issuer, "aws", "123456789012"); apiErr == nil {
			t.Fatalf("unconfigured issuer format accepted: %s", issuer)
		}
	}
}
