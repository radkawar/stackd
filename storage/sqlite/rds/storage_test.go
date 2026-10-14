package rds_test

import (
	"errors"
	"path/filepath"
	"testing"

	domain "stackd/storage/rds"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/rds"
)

func TestAllocatedStorageSurvivesRollbackRestartAndScopeIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capacity.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := backend.New(db)
	key := domain.Key{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: "db", Name: "owned"}
	snapshotKey := key
	snapshotKey.Kind = "snapshot"
	original := domain.Database{Key: key, Username: "lindm_admin", AllocatedStorage: 20, RuntimeID: "native-engine", Status: "available"}
	if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutDatabase(original); err != nil {
			return err
		}
		return tx.PutSnapshot(domain.Snapshot{Key: snapshotKey, Source: key.Name, AllocatedStorage: 20})
	}); err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("reject command")
	if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
		changed := original
		changed.AllocatedStorage = 30
		if err := tx.PutDatabase(changed); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repo = backend.New(db)
	if err := repo.View(t.Context(), func(r domain.Reader) error {
		got, err := r.Database(key)
		if err != nil {
			return err
		}
		if got.AllocatedStorage != 20 || got.Username != "lindm_admin" || got.RuntimeID != original.RuntimeID {
			t.Fatalf("capacity/name escaped rollback or restart: %#v", got)
		}
		snapshot, err := r.Snapshot(snapshotKey)
		if err != nil {
			return err
		}
		if snapshot.AllocatedStorage != 20 {
			t.Fatalf("snapshot capacity lost: %#v", snapshot)
		}
		for _, alien := range []domain.Scope{{Partition: "aws", AccountID: "222222222222", Region: "us-east-1"}, {Partition: "aws", AccountID: "111111111111", Region: "us-west-2"}} {
			foreign := key
			foreign.Scope = alien
			if _, err := r.Database(foreign); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("capacity crossed scope: %v", err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
		changed := original
		changed.AllocatedStorage = 30
		return tx.PutDatabase(changed)
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.View(t.Context(), func(r domain.Reader) error {
		got, err := r.Database(key)
		if err == nil && got.AllocatedStorage != 30 {
			t.Fatalf("upsert lost capacity: %#v", got)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
