package storage_test

import (
	"errors"
	"testing"

	"stackd/storage/identity"
	"stackd/storage/kms"
	"stackd/storage/memory"
)

func TestCredentialTransactionClosesAtCallbackBoundary(t *testing.T) {
	repository := identity.NewMemory()
	var escaped identity.Transaction
	if err := repository.Update(t.Context(), func(tx identity.Transaction) error {
		escaped = tx
		return tx.Put(identity.Record{Credential: identity.Credential{AccessKeyID: "key"}})
	}); err != nil {
		t.Fatal(err)
	}
	if err := escaped.Delete("key"); !errors.Is(err, memory.ErrClosedTransaction) {
		t.Fatalf("escaped delete: %v", err)
	}
	if _, err := escaped.Get("key"); !errors.Is(err, memory.ErrClosedTransaction) {
		t.Fatalf("escaped read: %v", err)
	}
	if err := repository.View(t.Context(), func(r identity.Reader) error { _, err := r.Get("key"); return err }); err != nil {
		t.Fatal("escaped transaction changed committed state:", err)
	}
}

func TestKeyTransactionClosesAtCallbackBoundary(t *testing.T) {
	backend := kms.NewMemory(nil)
	scope := kms.StorageScope{Partition: "aws", AccountID: "000000000000", Region: "us-east-1"}
	owner := kms.KeyOwner{Partition: scope.Partition, AccountID: scope.AccountID}
	var escaped kms.Transaction
	if err := backend.Transact(t.Context(), func(tx kms.Transaction) error {
		escaped = tx
		if err := tx.PutKeySet(owner, kms.KeySetRecord{ID: "key", PrimaryRegion: scope.Region, Materials: []kms.KeyMaterialRecord{{Material: []byte("material")}}}); err != nil {
			return err
		}
		return tx.PutKey(scope, kms.KeyRecord{ID: "key"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := escaped.DeleteKey(scope, "key"); !errors.Is(err, memory.ErrClosedTransaction) {
		t.Fatalf("escaped delete: %v", err)
	}
	if _, err := escaped.Keys(scope); !errors.Is(err, memory.ErrClosedTransaction) {
		t.Fatalf("escaped read: %v", err)
	}
	if err := backend.Transact(t.Context(), func(tx kms.Transaction) error {
		keys, err := tx.Keys(scope)
		if err != nil {
			return err
		}
		set, err := tx.KeySet(owner, "key")
		if err != nil {
			return err
		}
		if len(keys) != 1 || string(set.Materials[0].Material) != "material" {
			t.Fatal("escaped transaction changed committed state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
