package identity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"stackd/clock"
)

func rootSessionSpec() RootSessionSpec {
	return RootSessionSpec{AccountID: "999999999999", Partition: "aws", Duration: 15 * time.Minute,
		TaskPolicyARN:      "arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials",
		TaskPolicyDocument: `{"Version":"2012-10-17","Statement":{"Effect":"Deny","NotAction":"iam:GetAccountSummary","Resource":"*"}}`}
}

func TestRootSessionScopeExpirationAndCopies(t *testing.T) {
	for _, epoch := range []time.Time{time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC), {}} {
		t.Run(epoch.Format(time.RFC3339), func(t *testing.T) {
			manual := clock.NewManual(epoch)
			store := NewWithConfig(Config{AccountID: "123456789012", Clock: manual, Repository: NewMemoryRepository()})
			parent, err := store.CreateAccessKey(testPrincipal())
			if err != nil {
				t.Fatal(err)
			}
			spec := rootSessionSpec()
			c, err := store.IssueRootSession(t.Context(), parent, spec)
			if err != nil {
				t.Fatal(err)
			}
			if c.AccountID != spec.AccountID || c.PrincipalID != spec.AccountID || c.PrincipalARN != "arn:aws:iam::999999999999:root" || c.SessionType != SessionTypeAssumeRoot || c.SessionToken == "" || !c.HasSessionPolicy {
				t.Fatal("root credential principal or scope is incomplete")
			}
			if c.IssuerARN != "" || c.IssuerID != "" || c.UserName != "" || c.MFAPresent || !c.CreateDate.Equal(epoch) || !c.Expiration.Equal(epoch.Add(spec.Duration)) {
				t.Fatal("root credential retained unrelated parent attributes or wrong times")
			}
			c.SessionPolicies[0], c.SessionPolicyARNs[0] = "altered", "altered"
			resolved, err := store.Resolve(t.Context(), c.AccessKeyID)
			if err != nil || resolved.SessionPolicies[0] != spec.TaskPolicyDocument || resolved.SessionPolicyARNs[0] != spec.TaskPolicyARN {
				t.Fatal("returned root credential aliases stored scope", err)
			}
			advanceIdentityClock(t, manual, spec.Duration)
			if _, err := store.Resolve(t.Context(), c.AccessKeyID); !errors.Is(err, ErrExpired) {
				t.Fatalf("exact expiry: %v", err)
			}
			spec.Duration = 0
			zeroStore := NewWithConfig(Config{AccountID: "123456789012", Clock: clock.NewManual(epoch), Repository: NewMemoryRepository()})
			zeroParent, err := zeroStore.CreateAccessKey(testPrincipal())
			if err != nil {
				t.Fatal(err)
			}
			zero, err := zeroStore.IssueRootSession(t.Context(), zeroParent, spec)
			if err != nil || !zero.Expiration.Equal(epoch) {
				t.Fatal("duration zero was not issued at the transaction instant", err)
			}
			if _, err := zeroStore.Resolve(t.Context(), zero.AccessKeyID); !errors.Is(err, ErrExpired) {
				t.Fatalf("zero-duration root token must be expired even at modeled zero time: %v", err)
			}
		})
	}
}

func TestRootSessionUsesCurrentCallerAndTransactionTime(t *testing.T) {
	epoch := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	manual := clock.NewManual(epoch)
	base := NewMemoryRepository()
	repository := &clockHookRepository{Repository: base}
	store := NewWithConfig(Config{AccountID: "123456789012", Repository: repository, Clock: manual})
	user, err := store.CreateAccessKey(testPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	role, err := store.IssueRoleSession(t.Context(), user, RoleSessionSpec{Role: Principal{AccountID: user.AccountID, ARN: "arn:aws:iam::123456789012:role/observer", ID: "AROAOBSERVER"}, SessionName: "source", SourceIdentity: "verified-source", Duration: time.Hour, MaxSessionDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	role.SourceIdentity = "stale-or-forged-value"
	repository.before = func() { advanceIdentityClock(t, manual, time.Minute) }
	repository.afterRead = func() { advanceIdentityClock(t, manual, time.Hour) }
	c, err := store.IssueRootSession(t.Context(), role, rootSessionSpec())
	if err != nil {
		t.Fatal(err)
	}
	if c.SourceIdentity != "verified-source" || !c.CreateDate.Equal(epoch.Add(time.Minute)) || !c.Expiration.Equal(epoch.Add(16*time.Minute)) {
		t.Fatal("root session used stale parent claims or multiple instants")
	}
	persisted := readClockRecord(t, base, c.AccessKeyID)
	if persisted.Credential.SourceIdentity != c.SourceIdentity || !persisted.Credential.Expiration.Equal(c.Expiration) {
		t.Fatal("persisted root session differs from issued snapshot")
	}
	if _, err := store.IssueRootSession(t.Context(), role, rootSessionSpec()); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired role parent minted root credentials: %v", err)
	}
}

func TestRootSessionRejectsInvalidScopeAndParents(t *testing.T) {
	store := NewStore("123456789012")
	user, err := store.CreateAccessKey(testPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	root, err := store.Resolve(t.Context(), "test")
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.IssueSession(t.Context(), user, SessionSpec{Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	federated, err := store.IssueFederation(t.Context(), user, FederationSpec{Name: "federated", Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, parent := range []Credential{root, token, federated} {
		if _, err := store.IssueRootSession(t.Context(), parent, rootSessionSpec()); !errors.Is(err, ErrInvalidPrincipal) {
			t.Fatalf("unsupported caller accepted: %v", err)
		}
	}
	for _, mutate := range []func(*RootSessionSpec){
		func(s *RootSessionSpec) { s.AccountID = "bad" },
		func(s *RootSessionSpec) { s.Partition = "aws-cn" },
		func(s *RootSessionSpec) { s.TaskPolicyARN = "arn:aws:iam::aws:policy/AdministratorAccess" },
		func(s *RootSessionSpec) { s.TaskPolicyDocument = "" },
		func(s *RootSessionSpec) { s.Duration = -time.Second },
		func(s *RootSessionSpec) { s.Duration = 901 * time.Second },
	} {
		spec := rootSessionSpec()
		mutate(&spec)
		if _, err := store.IssueRootSession(t.Context(), user, spec); err == nil {
			t.Fatal("invalid root session specification accepted")
		}
	}
	issued, err := store.IssueRootSession(t.Context(), user, rootSessionSpec())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.IssueRootSession(t.Context(), issued, rootSessionSpec()); !errors.Is(err, ErrInvalidPrincipal) {
		t.Fatalf("root session chained into a new root session: %v", err)
	}
}

func TestRootSessionOuterRollbackCancellationAndConcurrency(t *testing.T) {
	store := NewStore("123456789012")
	parent, err := store.CreateAccessKey(testPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	for _, cancelCommit := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		aborted := errors.New("commit failed")
		var issued Credential
		err := store.WithTransaction(ctx, func(ctx context.Context, borrowed *Store, _ time.Time) error {
			var err error
			issued, err = borrowed.IssueRootSession(ctx, parent, rootSessionSpec())
			if err != nil {
				return err
			}
			if cancelCommit {
				cancel()
				return nil
			}
			return aborted
		})
		cancel()
		if err == nil {
			t.Fatal("failed/canceled transaction succeeded")
		}
		if _, err := store.Resolve(t.Context(), issued.AccessKeyID); !errors.Is(err, ErrNotFound) {
			t.Fatal("failed/canceled commit retained root credentials", err)
		}
	}
	var workers sync.WaitGroup
	results := make(chan error, 16)
	for range 16 {
		workers.Go(func() {
			_, err := store.IssueRootSession(t.Context(), parent, rootSessionSpec())
			results <- err
		})
	}
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	err = store.repository.View(t.Context(), func(r Reader) error {
		rows, err := r.FindPrincipal("999999999999", "999999999999")
		if len(rows) != 16 {
			t.Errorf("persisted %d root sessions, want16", len(rows))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
