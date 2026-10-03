package account_test

import (
	"errors"
	"testing"
	"time"

	"stackd/clock"
	identity "stackd/internal/services/iam"
	organization "stackd/internal/services/organizations"
	"stackd/storage"
	"stackd/storage/account"
	"stackd/storage/iam"
)

func TestAccountIdentityWritesRollBackTogether(t *testing.T) {
	backends := storage.NewMemory()
	source := clock.NewManual(time.Unix(0, 0).UTC())
	registry := organization.NewWithConfig(organization.Config{Storage: backends.Organizations, Clock: source})
	identity := identity.NewWithConfig(identity.Config{Repository: backends.IAM, Clock: source})
	identity.SetAccountIdentitySource(registry)
	t.Cleanup(func() { _ = registry.Close(); _ = identity.Close() })
	scope := iam.Scope{Partition: "aws", AccountID: "111111111111"}
	rejected := errors.New("account operation failed")
	err := backends.Account.Update(t.Context(), func(tx account.Writer) error {
		if err := registry.PutAccountName(tx.Context(), scope.Partition, scope.AccountID, "Renamed"); err != nil {
			return err
		}
		if _, err := identity.AccountCreationTime(tx.Context(), scope.Partition, scope.AccountID); err != nil {
			return err
		}
		return rejected
	})
	if !errors.Is(err, rejected) {
		t.Fatal(err)
	}
	registered, _, err := backends.Organizations.Load(t.Context(), scope.Partition)
	if err != nil || len(registered.Accounts) != 0 {
		t.Fatal("failed operation retained registered name", err)
	}
	if err := backends.IAM.View(t.Context(), func(tx iam.ReadTx) error {
		_, err := tx.AccountMetadata(scope)
		if !errors.Is(err, iam.ErrRecordNotFound) {
			t.Fatalf("failed operation retained creation time: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	created, err := identity.AccountCreationTime(t.Context(), scope.Partition, scope.AccountID)
	if err != nil || !created.Equal(time.Unix(0, 0)) {
		t.Fatal("zero epoch initialization", created, err)
	}
	if err := source.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	later, err := identity.AccountCreationTime(t.Context(), scope.Partition, scope.AccountID)
	if err != nil || !later.Equal(created) {
		t.Fatal("persisted zero epoch creation time changed", later, err)
	}
}
