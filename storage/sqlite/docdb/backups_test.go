package docdb_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	domain "stackd/storage/docdb"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/docdb"
)

func TestAutomatedBackupIntentSurvivesReopenAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backups.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := backend.New(db)
	scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	created := time.Date(2031, 1, 1, 9, 0, 0, 0, time.UTC)
	cluster := domain.Cluster{Key: domain.Key{Scope: scope, Kind: "cluster", Name: "source"}, RuntimeID: "source-incarnation", BackupRetention: 2, BackupWindow: "09:00-09:30", NextBackup: created.Add(24 * time.Hour)}
	snapshot := domain.Snapshot{Key: domain.Key{Scope: scope, Kind: "cluster-snapshot", Name: "auto-source"}, Source: cluster.Key.Name, SourceRuntimeID: cluster.RuntimeID, RuntimeID: "snapshot-incarnation", Automated: true, Created: created, Expires: created.Add(48 * time.Hour), Due: created, Status: "creating", Operation: "create", Version: 1}
	if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutCluster(cluster); err != nil {
			return err
		}
		return tx.PutSnapshot(snapshot)
	}); err != nil {
		t.Fatal(err)
	}
	rejected := errors.New("reject transaction")
	if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
		changed := snapshot
		changed.Expires = created.Add(time.Hour)
		if err := tx.PutSnapshot(changed); err != nil {
			return err
		}
		return rejected
	}); !errors.Is(err, rejected) {
		t.Fatalf("rollback: %v", err)
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
		got, err := r.Cluster(cluster.Key)
		if err != nil {
			return err
		}
		if got.BackupRetention != 2 || got.BackupWindow != cluster.BackupWindow || !got.NextBackup.Equal(cluster.NextBackup) {
			t.Fatalf("backup policy lost on reopen: %#v", got)
		}
		copy, err := r.Snapshot(snapshot.Key)
		if err != nil {
			return err
		}
		if !copy.Automated || copy.SourceRuntimeID != cluster.RuntimeID || copy.RuntimeID != snapshot.RuntimeID || !copy.Expires.Equal(snapshot.Expires) || copy.Operation != "create" || copy.Version != 1 {
			t.Fatalf("backup ownership or rollback lost: %#v", copy)
		}
		foreign := snapshot.Key
		foreign.AccountID = "222222222222"
		if _, err := r.Snapshot(foreign); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("foreign snapshot exposed: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
