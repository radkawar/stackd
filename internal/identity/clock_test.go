package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/clock"
)

func TestIssueUsesTransactionInstant(t *testing.T) {
	ctx := context.Background()
	spec := RoleSessionSpec{
		Role:        Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:role/worker", ID: "AROAWORKER"},
		SessionName: "job", Duration: time.Hour, MaxSessionDuration: time.Hour,
	}
	cases := []struct {
		name  string
		issue func(*Store, Credential) (Credential, error)
	}{
		{"session", func(s *Store, parent Credential) (Credential, error) {
			return s.IssueSession(ctx, parent, SessionSpec{Duration: time.Hour})
		}},
		{"mfa_session", func(s *Store, parent Credential) (Credential, error) {
			return s.IssueSession(ctx, parent, SessionSpec{Duration: time.Hour, MFAPresent: true, MFAAuthenticatedAt: time.Time{}})
		}},
		{"role", func(s *Store, parent Credential) (Credential, error) {
			return s.IssueRoleSession(ctx, parent, spec)
		}},
		{"federation", func(s *Store, parent Credential) (Credential, error) {
			return s.IssueFederation(ctx, parent, FederationSpec{Name: "worker", Duration: time.Hour})
		}},
		{"federated_role", func(s *Store, _ Credential) (Credential, error) {
			return s.IssueFederatedRoleSession(ctx, spec)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
			manual := clock.NewManual(start)
			base := NewMemoryRepository()
			repository := &clockHookRepository{Repository: base}
			store := NewWithConfig(Config{AccountID: "123456789012", Repository: repository, Clock: manual})
			parent, err := store.CreateAccessKey(testPrincipal())
			if err != nil {
				t.Fatal(err)
			}
			// Waiting to enter a transaction must not freeze an earlier time.
			// Reads within the callback then advance time independently.
			repository.before = func() { advanceIdentityClock(t, manual, time.Minute) }
			repository.afterRead = func() { advanceIdentityClock(t, manual, time.Second) }
			issued, err := tc.issue(store, parent)
			if err != nil {
				t.Fatal(err)
			}
			want := start.Add(time.Minute)
			if !issued.CreateDate.Equal(want) || !issued.Expiration.Equal(want.Add(time.Hour)) {
				t.Fatalf("issued times = %v, %v; want %v, %v", issued.CreateDate, issued.Expiration, want, want.Add(time.Hour))
			}
			if !manual.Now().After(want) {
				t.Fatal("test did not advance the clock within the callback")
			}
			persisted := readClockRecord(t, base, issued.AccessKeyID)
			if !persisted.Credential.CreateDate.Equal(want) || !persisted.Credential.Expiration.Equal(issued.Expiration) {
				t.Fatal("persisted credential times differ from the transaction instant")
			}
		})
	}
}

func TestCreateAccessKeyUsesTransactionInstant(t *testing.T) {
	start := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	manual := clock.NewManual(start)
	repository := &clockHookRepository{
		Repository: NewMemoryRepository(),
		before:     func() { advanceIdentityClock(t, manual, time.Minute) },
		afterRead:  func() { advanceIdentityClock(t, manual, time.Second) },
	}
	store := NewWithConfig(Config{AccountID: "123456789012", Repository: repository, Clock: manual})
	credential, err := store.CreateAccessKey(testPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	if !credential.CreateDate.Equal(start.Add(time.Minute)) {
		t.Fatalf("CreateDate = %v, want %v", credential.CreateDate, start.Add(time.Minute))
	}
}

func TestCredentialExpiryUsesTransactionInstant(t *testing.T) {
	for _, operation := range []string{"resolve", "role_chain"} {
		for _, enterAtExpiry := range []bool{false, true} {
			name := operation + "/advance_during_read"
			if enterAtExpiry {
				name = operation + "/expired_before_callback"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				start := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
				manual := clock.NewManual(start)
				base := NewMemoryRepository()
				repository := &clockHookRepository{Repository: base}
				store := NewWithConfig(Config{AccountID: "123456789012", Repository: repository, Clock: manual})
				parent, err := store.Resolve(ctx, "test")
				if err != nil {
					t.Fatal(err)
				}
				spec := RoleSessionSpec{
					Role:        Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:role/worker", ID: "AROAWORKER"},
					SessionName: "job", Duration: time.Hour, MaxSessionDuration: time.Hour,
				}
				session, err := store.IssueRoleSession(ctx, parent, spec)
				if err != nil {
					t.Fatal(err)
				}
				advanceIdentityClock(t, manual, time.Hour-2*time.Second)
				wait := time.Second
				if enterAtExpiry {
					wait = 2 * time.Second
				}
				repository.before = func() { advanceIdentityClock(t, manual, wait) }
				repository.afterRead = func() { advanceIdentityClock(t, manual, 2*time.Second) }
				instant := session.Expiration.Add(-2*time.Second + wait)
				var issued Credential
				switch operation {
				case "resolve":
					_, err = store.Resolve(ctx, session.AccessKeyID)
				case "role_chain":
					issued, err = store.IssueRoleSession(ctx, session, spec)
				}
				if enterAtExpiry {
					if !errors.Is(err, ErrExpired) {
						t.Fatalf("operation at exact expiry returned %v", err)
					}
				} else if err != nil {
					t.Fatalf("credential valid at transaction entry was rejected: %v", err)
				}
				if operation == "role_chain" && !enterAtExpiry {
					if !issued.CreateDate.Equal(instant) || !issued.Expiration.Equal(instant.Add(time.Hour)) {
						t.Fatalf("role chain times = %v, %v; expected transaction instant %v", issued.CreateDate, issued.Expiration, instant)
					}
				}
			})
		}
	}
}

func TestZeroInstantMFAPresence(t *testing.T) {
	ctx := context.Background()
	store := NewWithConfig(Config{AccountID: "123456789012", Repository: NewMemoryRepository(), Clock: clock.NewManual(time.Time{})})
	parent, err := store.Resolve(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	without, err := store.IssueSession(ctx, parent, SessionSpec{Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	with, err := store.IssueSession(ctx, parent, SessionSpec{Duration: time.Hour, MFAPresent: true, MFAAuthenticatedAt: time.Time{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []Credential{without, with} {
		resolved, err := store.Resolve(ctx, c.AccessKeyID)
		if err != nil {
			t.Fatal(err)
		}
		wantMFA := c.AccessKeyID == with.AccessKeyID
		if c.MFAPresent != wantMFA || resolved.MFAPresent != wantMFA || !resolved.MFAAuthenticatedAt.IsZero() || !resolved.CreateDate.IsZero() {
			t.Fatalf("zero-time session MFA = %v, persisted = %v; want %v", c.MFAPresent, resolved.MFAPresent, wantMFA)
		}
	}
}

// These hooks model time passing while storage waits and reads. They make the
// transaction boundary observable without scheduling sleeps or clock stubs.
type clockHookRepository struct {
	Repository
	before, afterRead func()
}

func (r *clockHookRepository) View(ctx context.Context, fn func(Reader) error) error {
	return r.Repository.View(ctx, func(reader Reader) error {
		if r.before != nil {
			r.before()
		}
		return fn(clockHookReader{Reader: reader, afterRead: r.afterRead})
	})
}

func (r *clockHookRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return r.Repository.Update(ctx, func(tx Transaction) error {
		if r.before != nil {
			r.before()
		}
		return fn(clockHookTransaction{clockHookReader: clockHookReader{Reader: tx, afterRead: r.afterRead}, tx: tx})
	})
}

type clockHookReader struct {
	Reader
	afterRead func()
}

func (r clockHookReader) Get(key string) (Record, error) {
	record, err := r.Reader.Get(key)
	if r.afterRead != nil {
		r.afterRead()
	}
	return record, err
}

func (r clockHookReader) FindPrincipal(account, id string) ([]Record, error) {
	records, err := r.Reader.FindPrincipal(account, id)
	if r.afterRead != nil {
		r.afterRead()
	}
	return records, err
}

type clockHookTransaction struct {
	clockHookReader
	tx Transaction
}

func (t clockHookTransaction) Put(record Record) error { return t.tx.Put(record) }
func (t clockHookTransaction) Delete(key string) error { return t.tx.Delete(key) }

func advanceIdentityClock(t *testing.T, manual *clock.Manual, d time.Duration) {
	t.Helper()
	if err := manual.Advance(d); err != nil {
		t.Fatal(err)
	}
}

func readClockRecord(t *testing.T, repository Repository, key string) Record {
	t.Helper()
	var record Record
	err := repository.View(context.Background(), func(reader Reader) error {
		var err error
		record, err = reader.Get(key)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}
