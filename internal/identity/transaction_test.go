package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/clock"
)

func TestBorrowedCredentialTransactionRollbackAndLifetime(t *testing.T) {
	for _, failure := range []string{"none", "callback", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			epoch := time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)
			source := clock.NewManual(epoch)
			repository := NewMemoryRepository()
			store := NewWithConfig(Config{Repository: repository, Clock: source})
			parent, err := store.Resolve(t.Context(), "test")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var escaped *Store
			var escapedCtx context.Context
			var issued Credential
			callbackError := errors.New("reject issuance")
			err = store.WithTransaction(ctx, func(ctx context.Context, borrowed *Store, instant time.Time) error {
				escaped, escapedCtx = borrowed, ctx
				if !instant.Equal(epoch) {
					t.Error("incorrect captured instant")
				}
				if err := source.Advance(time.Minute); err != nil {
					return err
				}
				var err error
				issued, err = borrowed.IssueSession(ctx, parent, SessionSpec{Duration: 15 * time.Minute})
				if err != nil {
					return err
				}
				if !issued.CreateDate.Equal(epoch) || !issued.Expiration.Equal(epoch.Add(15*time.Minute)) {
					t.Error("borrowed store sampled time outside the transaction")
				}
				if _, err := borrowed.Resolve(ctx, issued.AccessKeyID); err != nil {
					return err
				}
				if failure == "callback" {
					return callbackError
				}
				if failure == "cancel" {
					cancel()
				}
				return nil
			})
			switch failure {
			case "none":
				if err != nil {
					t.Fatal(err)
				}
			case "callback":
				if !errors.Is(err, callbackError) {
					t.Fatalf("callback error = %v", err)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation = %v", err)
				}
			}
			_, err = store.Resolve(t.Context(), issued.AccessKeyID)
			if failure == "none" && err != nil || failure != "none" && !errors.Is(err, ErrNotFound) {
				t.Fatalf("committed credential after %s: %v", failure, err)
			}
			if !errors.Is(escapedCtx.Err(), context.Canceled) {
				t.Error("callback context remained valid")
			}
			if _, err := escaped.Resolve(t.Context(), "test"); !errors.Is(err, context.Canceled) {
				t.Fatalf("escaped credential read = %v", err)
			}
			if _, err := escaped.IssueSession(t.Context(), parent, SessionSpec{Duration: 15 * time.Minute}); !errors.Is(err, context.Canceled) {
				t.Fatalf("escaped credential issuance = %v", err)
			}
		})
	}
}

func TestCredentialTransactionRejectsReentry(t *testing.T) {
	store := NewStore("")
	err := store.WithTransaction(t.Context(), func(ctx context.Context, borrowed *Store, _ time.Time) error {
		for _, target := range []*Store{store, borrowed} {
			if err := target.WithTransaction(ctx, func(context.Context, *Store, time.Time) error {
				t.Error("re-entry called the nested callback")
				return nil
			}); err == nil {
				t.Error("re-entry accepted")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
