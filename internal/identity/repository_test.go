package identity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRepositoryRollbackAndDetachedSessionState(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository()
	first := NewWithRepository("123456789012", repository)
	root, err := first.Resolve(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	spec := RoleSessionSpec{Role: Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:role/path/worker", ID: "AROAWORKER"}, SessionName: "job", Duration: time.Hour, MaxSessionDuration: time.Hour, Policies: []string{`{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}}`}, HasSessionPolicy: true, Tags: map[string]string{"team": "payments"}}
	session, err := first.IssueRoleSession(ctx, root, spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Tags["team"] = "forged"
	spec.Policies[0] = "forged"
	session.SessionTags["team"] = "also-forged"
	second := NewWithRepository("123456789012", repository)
	resolved, err := second.Resolve(ctx, session.AccessKeyID)
	if err != nil || resolved.SessionTags["team"] != "payments" || resolved.SessionPolicies[0] == "forged" {
		t.Fatalf("repository lost or leaked session: %v, %v", resolved, err)
	}
	aborted := errors.New("transaction aborted")
	err = repository.Update(ctx, func(tx Transaction) error {
		r, err := tx.Get(session.AccessKeyID)
		if err != nil {
			return err
		}
		r.Credential.SessionTags["team"] = "rollback"
		if err := tx.Put(r); err != nil {
			return err
		}
		if err := tx.Delete(session.AccessKeyID); err != nil {
			return err
		}
		return aborted
	})
	if !errors.Is(err, aborted) {
		t.Fatal(err)
	}
	resolved, err = second.Resolve(ctx, session.AccessKeyID)
	if err != nil || resolved.SessionTags["team"] != "payments" {
		t.Fatalf("failed transaction changed session: %v, %v", resolved, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	err = repository.Update(canceled, func(tx Transaction) error {
		if err := tx.Delete(session.AccessKeyID); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := second.Resolve(ctx, session.AccessKeyID); err != nil {
		t.Fatalf("canceled commit deleted credential: %v", err)
	}
	if err := second.DeletePrincipal("123456789012", "AROAWORKER"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Resolve(ctx, session.AccessKeyID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("role deletion retained session: %v", err)
	}
}

func TestSharedRepositorySerializesQuotaAcrossStores(t *testing.T) {
	repository := NewMemoryRepository()
	stores := []*Store{NewWithRepository("123456789012", repository), NewWithRepository("123456789012", repository)}
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := range 20 {
		wg.Go(func() { _, err := stores[i%2].CreateAccessKey(testPrincipal()); results <- err })
	}
	wg.Wait()
	close(results)
	created := 0
	for err := range results {
		if err == nil {
			created++
		} else if !errors.Is(err, ErrLimitExceeded) {
			t.Fatal(err)
		}
	}
	if created != 2 {
		t.Fatalf("created %d keys across stores, want 2", created)
	}
}

func TestRoleChainAndFederationCredentialRestrictions(t *testing.T) {
	store := NewStore("123456789012")
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	ctx := context.Background()
	root, err := store.Resolve(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	spec := RoleSessionSpec{Role: Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:role/path/worker", ID: "AROAWORKER"}, SessionName: "job", Duration: 2 * time.Hour, MaxSessionDuration: 12 * time.Hour}
	role, err := store.IssueRoleSession(ctx, root, spec)
	if err != nil {
		t.Fatal(err)
	}
	if role.PrincipalARN != "arn:aws:sts::123456789012:assumed-role/worker/job" || role.PrincipalID != "AROAWORKER:job" {
		t.Fatalf("wrong role principal: %v", role)
	}
	if _, err := store.IssueRoleSession(ctx, role, spec); !errors.Is(err, ErrInvalidDuration) {
		t.Fatalf("role chain duration: %v", err)
	}
	spec.Duration = time.Hour
	chained, err := store.IssueRoleSession(ctx, role, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.IssueSession(ctx, chained, SessionSpec{Duration: time.Hour}); !errors.Is(err, ErrSessionCredentials) {
		t.Fatalf("role GetSessionToken: %v", err)
	}
	if _, err := store.IssueFederation(ctx, chained, FederationSpec{Name: "federated", Duration: time.Hour}); !errors.Is(err, ErrSessionCredentials) {
		t.Fatalf("role federation: %v", err)
	}
	federation, err := store.IssueFederation(ctx, root, FederationSpec{Name: "federated", Duration: 36 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !federation.Expiration.Equal(now.Add(time.Hour)) || !federation.HasSessionPolicy || federation.IssuerID != root.PrincipalID {
		t.Fatalf("root federation scope: %v", federation)
	}
	if _, err := store.IssueRoleSession(ctx, federation, spec); !errors.Is(err, ErrSessionCredentials) {
		t.Fatalf("federation role assumption: %v", err)
	}
	now = now.Add(time.Hour)
	if _, err := store.Resolve(ctx, chained.AccessKeyID); !errors.Is(err, ErrExpired) {
		t.Fatalf("role exact expiry: %v", err)
	}
}
