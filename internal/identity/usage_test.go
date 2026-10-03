package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"stackd/clock"
)

func TestAccessKeyUsageKeepsFirstObservationInFifteenMinuteSpan(t *testing.T) {
	for _, start := range []time.Time{{}, time.Unix(0, 0).UTC(), time.Date(2037, 4, 5, 6, 7, 8, 0, time.UTC)} {
		t.Run(start.Format(time.RFC3339), func(t *testing.T) {
			manual := clock.NewManual(start)
			store := NewWithConfig(Config{AccountID: "123456789012", Repository: NewMemoryRepository(), Clock: manual})
			key, err := store.CreateAccessKey(testPrincipal())
			if err != nil {
				t.Fatal(err)
			}
			read := func() LastUsed {
				t.Helper()
				_, usage, err := store.AccessKeyLastUsed(key.AccountID, key.AccessKeyID)
				if err != nil {
					t.Fatal(err)
				}
				return usage
			}
			if read().Recorded() {
				t.Fatal("new credential has usage")
			}
			use := func(service, region string) {
				t.Helper()
				if err := store.RecordUsage(t.Context(), key.AccessKeyID, service, region); err != nil {
					t.Fatal(err)
				}
			}
			use("iam", "us-east-1")
			first := read()
			if !first.Recorded() || !first.Date.Equal(start) || first.Service != "iam" || first.Region != "N/A" {
				t.Fatalf("first use=%+v", first)
			}
			for _, delta := range []time.Duration{5 * time.Minute, 10*time.Minute - time.Nanosecond} {
				advanceIdentityClock(t, manual, delta)
				use("kms", "eu-west-1")
				if got := read(); got != first {
					t.Fatalf("usage inside span changed date/service/region: %+v", got)
				}
			}
			advanceIdentityClock(t, manual, time.Nanosecond)
			use("sts", "ap-south-1")
			second := read()
			if !second.Date.Equal(start.Add(15*time.Minute)) || second.Service != "sts" || second.Region != "ap-south-1" {
				t.Fatalf("use at exact span boundary=%+v", second)
			}
			// Earlier timestamps cannot move the recorded observation backward.
			store.now = func() time.Time { return start.Add(-time.Second) }
			use("sqs", "eu-central-1")
			if got := read(); got != second {
				t.Fatalf("backward clock changed usage: %+v", got)
			}
		})
	}
}

func TestConcurrentAccessKeyUsageDoesNotMixObservationFields(t *testing.T) {
	manual := clock.NewManual(time.Date(2037, 4, 5, 6, 7, 8, 0, time.UTC))
	store := NewWithConfig(Config{AccountID: "123456789012", Repository: NewMemoryRepository(), Clock: manual})
	key, err := store.CreateAccessKey(testPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	errors := make(chan error, 24)
	for index := range 24 {
		group.Go(func() {
			suffix := fmt.Sprint(index)
			errors <- store.RecordUsage(t.Context(), key.AccessKeyID, "service-"+suffix, "region-"+suffix)
		})
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	_, got, err := store.AccessKeyLastUsed(key.AccountID, key.AccessKeyID)
	if err != nil || !got.Date.Equal(manual.Now()) || strings.TrimPrefix(got.Service, "service-") != strings.TrimPrefix(got.Region, "region-") {
		t.Fatalf("mixed concurrent usage=%+v, %v", got, err)
	}
}

func TestTemporaryUsageRemainsCurrentAndMonotonic(t *testing.T) {
	start := time.Date(2037, 4, 5, 6, 7, 8, 0, time.UTC)
	manual := clock.NewManual(start)
	repository := NewMemoryRepository()
	store := NewWithConfig(Config{AccountID: "123456789012", Repository: repository, Clock: manual})
	parent, err := store.Resolve(t.Context(), "test")
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.IssueSession(t.Context(), parent, SessionSpec{Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordUsage(t.Context(), session.AccessKeyID, "sqs", "us-east-1"); err != nil {
		t.Fatal(err)
	}
	advanceIdentityClock(t, manual, time.Second)
	if err := store.RecordUsage(t.Context(), session.AccessKeyID, "kms", "eu-west-1"); err != nil {
		t.Fatal(err)
	}
	got := readClockRecord(t, repository, session.AccessKeyID).LastUsed
	if !got.Date.Equal(start.Add(time.Second)) || got.Service != "kms" || got.Region != "eu-west-1" {
		t.Fatalf("temporary credentials were coalesced: %+v", got)
	}
	store.now = func() time.Time { return start }
	if err := store.RecordUsage(t.Context(), session.AccessKeyID, "iam", "us-east-1"); err != nil {
		t.Fatal(err)
	}
	if current := readClockRecord(t, repository, session.AccessKeyID).LastUsed; current != got {
		t.Fatalf("temporary usage moved backward: %+v", current)
	}
}

func TestUsageRollsBackWithEnclosingTransaction(t *testing.T) {
	store := NewStore("123456789012")
	key, err := store.CreateAccessKey(testPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	abort := errors.New("abort usage")
	err = store.WithTransaction(t.Context(), func(ctx context.Context, borrowed *Store, _ time.Time) error {
		if err := borrowed.RecordUsage(ctx, key.AccessKeyID, "iam", "us-east-1"); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	_, got, err := store.AccessKeyLastUsed(key.AccountID, key.AccessKeyID)
	if err != nil || got.Recorded() {
		t.Fatalf("aborted usage persisted: %+v, %v", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := store.RecordUsage(ctx, key.AccessKeyID, "sts", "eu-west-1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled usage=%v", err)
	}
}

func TestAcceptedUsageDoesNotReauthenticateCredentials(t *testing.T) {
	for _, state := range []string{"inactive", "expired", "deleted"} {
		t.Run(state, func(t *testing.T) {
			manual := clock.NewManual(time.Unix(0, 0).UTC())
			repository := NewMemoryRepository()
			store := NewWithConfig(Config{AccountID: "123456789012", Repository: repository, Clock: manual})
			key, err := store.CreateAccessKey(testPrincipal())
			if err != nil {
				t.Fatal(err)
			}
			wantAuthError := ErrInactive
			switch state {
			case "inactive":
				err = store.UpdateAccessKey(key.AccountID, key.PrincipalID, key.AccessKeyID, Inactive)
			case "expired":
				key, err = store.IssueSession(t.Context(), key, SessionSpec{Duration: time.Hour})
				advanceIdentityClock(t, manual, time.Hour)
				wantAuthError = ErrExpired
			case "deleted":
				err = store.DeleteAccessKey(key.AccountID, key.PrincipalID, key.AccessKeyID)
				wantAuthError = ErrNotFound
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Resolve(t.Context(), key.AccessKeyID); !errors.Is(err, wantAuthError) {
				t.Fatalf("new authentication=%v; want %v", err, wantAuthError)
			}
			if err := store.RecordUsage(t.Context(), key.AccessKeyID, "kms", "eu-west-1"); err != nil {
				t.Fatalf("accepted work was reauthenticated: %v", err)
			}
			if state == "deleted" {
				if err := repository.View(t.Context(), func(tx Reader) error {
					_, err := tx.Get(key.AccessKeyID)
					return err
				}); !errors.Is(err, ErrNotFound) {
					t.Fatalf("recording recreated a deleted credential: %v", err)
				}
				return
			}
			usage := readClockRecord(t, repository, key.AccessKeyID).LastUsed
			if usage.Service != "kms" || usage.Region != "eu-west-1" || !usage.Date.Equal(manual.Now()) {
				t.Fatalf("accepted usage=%+v", usage)
			}
		})
	}
}

func TestAcceptedUsageCapturesTransactionTimeBeforeReads(t *testing.T) {
	start := time.Unix(0, 0).UTC()
	manual := clock.NewManual(start)
	base := NewMemoryRepository()
	repository := &clockHookRepository{Repository: base}
	store := NewWithConfig(Config{AccountID: "123456789012", Repository: repository, Clock: manual})
	key, err := store.CreateAccessKey(testPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	repository.before = func() { advanceIdentityClock(t, manual, time.Minute) }
	repository.afterRead = func() { advanceIdentityClock(t, manual, time.Second) }
	if err := store.RecordUsage(t.Context(), key.AccessKeyID, "iam", "us-east-1"); err != nil {
		t.Fatal(err)
	}
	usage := readClockRecord(t, base, key.AccessKeyID).LastUsed
	if !usage.Date.Equal(start.Add(time.Minute)) || usage.Service != "iam" || usage.Region != "N/A" {
		t.Fatalf("usage sampled time after repository read: %+v", usage)
	}
}
