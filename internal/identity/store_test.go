package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func testPrincipal() Principal {
	return Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/engineering/Alice", ID: "AIDATESTPRINCIPAL", UserName: "Alice"}
}

func TestBootstrapRoots(t *testing.T) {
	s := NewStore("")
	for key, account := range map[string]string{"test": "000000000000", "123456789012": "123456789012"} {
		c, err := s.Resolve(context.Background(), key)
		if err != nil || c.AccountID != account || c.PrincipalID != account || c.SecretAccessKey != "test" || c.PrincipalARN != "arn:aws:iam::"+account+":root" {
			t.Fatalf("root identity: %v, %v", c, err)
		}
	}
	_, err := s.Resolve(context.Background(), "AKIAUNKNOWNKEY1234567")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown credential = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Resolve(ctx, "test")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled resolve = %v", err)
	}
}

func TestAccessKeyOwnershipStatusUsageAndRename(t *testing.T) {
	s := NewStore("123456789012")
	ctx := context.Background()
	p := testPrincipal()
	first, err := s.CreateAccessKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.AccessKeyID) != 20 || !strings.HasPrefix(first.AccessKeyID, "AKIA") || len(first.SecretAccessKey) != 40 {
		t.Fatalf("credential format: %v", first)
	}
	if _, err := s.CreateAccessKey(p); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAccessKey(p.AccountID, p.ID, first.AccessKeyID, Inactive); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, first.AccessKeyID); !errors.Is(err, ErrInactive) {
		t.Fatalf("inactive credential resolved: %v", err)
	}
	if _, err := s.CreateAccessKey(p); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("inactive key did not count against quota: %v", err)
	}
	if err := s.DeleteAccessKey("999999999999", p.ID, first.AccessKeyID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-account delete: %v", err)
	}
	if err := s.DeleteAccessKey(p.AccountID, "OTHERUSER", first.AccessKeyID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-user delete: %v", err)
	}
	_, usage, err := s.AccessKeyLastUsed(p.AccountID, first.AccessKeyID)
	if err != nil || !usage.Date.IsZero() || usage.Service != "N/A" || usage.Region != "N/A" {
		t.Fatalf("unused key: %+v, %v", usage, err)
	}
	if err := s.UpdateAccessKey(p.AccountID, p.ID, first.AccessKeyID, Active); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordUsage(ctx, first.AccessKeyID, "s3", "eu-west-1"); err != nil {
		t.Fatal(err)
	}
	_, usage, err = s.AccessKeyLastUsed(p.AccountID, first.AccessKeyID)
	if err != nil || usage.Date.IsZero() || usage.Service != "s3" || usage.Region != "eu-west-1" {
		t.Fatalf("recorded usage: %+v, %v", usage, err)
	}
	p.UserName, p.ARN = "Alicia", "arn:aws:iam::123456789012:user/staff/Alicia"
	if err := s.RenamePrincipal(p); err != nil {
		t.Fatal(err)
	}
	resolved, err := s.Resolve(ctx, first.AccessKeyID)
	if err != nil || resolved.UserName != p.UserName || resolved.PrincipalARN != p.ARN || resolved.PrincipalID != first.PrincipalID || resolved.SecretAccessKey != first.SecretAccessKey {
		t.Fatalf("renamed credential: %v, %v", resolved, err)
	}
	if err := s.DeleteAccessKey(p.AccountID, p.ID, first.AccessKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, first.AccessKeyID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted key resolved: %v", err)
	}
	if _, err := s.CreateAccessKey(p); err != nil {
		t.Fatalf("deleted slot was not reusable: %v", err)
	}
}

func TestConcurrentAccessKeyQuota(t *testing.T) {
	s := NewStore("123456789012")
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for range 20 {
		wg.Go(func() { _, err := s.CreateAccessKey(testPrincipal()); results <- err })
	}
	wg.Wait()
	close(results)
	created, limited := 0, 0
	for err := range results {
		if err == nil {
			created++
		} else if errors.Is(err, ErrLimitExceeded) {
			limited++
		} else {
			t.Fatal(err)
		}
	}
	if created != 2 || limited != 18 {
		t.Fatalf("quota outcomes = %d created, %d limited", created, limited)
	}
}

func TestSessionDurationExpiryAndSourceIndependence(t *testing.T) {
	s := NewStore("123456789012")
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	ctx := context.Background()
	p := testPrincipal()
	user, err := s.CreateAccessKey(p)
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.IssueSession(ctx, user, SessionSpec{Duration: 36 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(session.AccessKeyID, "ASIA") || session.SessionToken == "" || session.SessionType != SessionTypeGetSessionToken || !session.Expiration.Equal(now.Add(36*time.Hour)) || session.PrincipalID != user.PrincipalID {
		t.Fatalf("session = %v", session)
	}
	if _, err := s.IssueSession(ctx, session, SessionSpec{Duration: time.Hour}); !errors.Is(err, ErrSessionCredentials) {
		t.Fatalf("session chaining = %v", err)
	}
	if err := s.DeleteAccessKey(p.AccountID, p.ID, user.AccessKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, session.AccessKeyID); err != nil {
		t.Fatalf("deleting source key revoked session: %v", err)
	}
	root, err := s.Resolve(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	rootSession, err := s.IssueSession(ctx, root, SessionSpec{Duration: 36 * time.Hour})
	if err != nil || !rootSession.Expiration.Equal(now.Add(time.Hour)) {
		t.Fatalf("root duration cap: %v, %v", rootSession, err)
	}
	for _, duration := range []time.Duration{0, 899 * time.Second, 36*time.Hour + time.Second} {
		if _, err := s.IssueSession(ctx, root, SessionSpec{Duration: duration}); !errors.Is(err, ErrInvalidDuration) {
			t.Fatalf("invalid duration %v: %v", duration, err)
		}
	}
	now = now.Add(time.Hour)
	if _, err := s.Resolve(ctx, rootSession.AccessKeyID); !errors.Is(err, ErrExpired) {
		t.Fatalf("exact expiry boundary: %v", err)
	}
	if err := s.DeletePrincipal(p.AccountID, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, session.AccessKeyID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted principal retained session: %v", err)
	}
}

func TestServiceRoleLifetimeDoesNotRelaxUserOrFederationLimits(t *testing.T) {
	store := NewStore("123456789012")
	now := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	parent, err := store.CreateAccessKey(testPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	spec := RoleSessionSpec{
		Role:        Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:role/worker", ID: "AROAWORKER"},
		SessionName: "i-0123456789abcdef0", Duration: 6*time.Hour + 35*time.Minute, MaxSessionDuration: time.Hour,
	}
	for name, issue := range map[string]func(context.Context, RoleSessionSpec) (Credential, error){
		"federated": store.IssueFederatedRoleSession,
		"user": func(ctx context.Context, spec RoleSessionSpec) (Credential, error) {
			return store.IssueRoleSession(ctx, parent, spec)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := issue(t.Context(), spec); !errors.Is(err, ErrInvalidDuration) {
				t.Fatalf("caller bypassed role's session maximum: %v", err)
			}
		})
	}
	service, err := store.IssueServiceRoleSession(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := store.Resolve(t.Context(), service.AccessKeyID); err != nil {
		t.Fatalf("AWS service credential expired at caller role limit: %v", err)
	}
	if want := service.CreateDate.Add(spec.Duration); !service.Expiration.Equal(want) {
		t.Fatalf("service expiration = %s, want %s", service.Expiration, want)
	}
	now = service.Expiration
	if _, err := store.Resolve(t.Context(), service.AccessKeyID); !errors.Is(err, ErrExpired) {
		t.Fatalf("service credential survived its own expiration: %v", err)
	}
}

func TestCredentialFormattingRedactsSecrets(t *testing.T) {
	c := Credential{AccessKeyID: "test-key", SecretAccessKey: "must-remain-secret", SessionToken: "must-remain-private"}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		printed := fmt.Sprintf(format, c)
		if strings.Contains(printed, c.SecretAccessKey) || strings.Contains(printed, c.SessionToken) {
			t.Fatalf("format %s exposed credential material", format)
		}
	}
}
