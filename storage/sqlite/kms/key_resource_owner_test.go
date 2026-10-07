package kms_test

import (
	"path/filepath"
	"testing"
	"time"

	"stackd/internal/awstest"
	owner "stackd/internal/services/kms"
	domain "stackd/storage/kms"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/kms"
)

func TestSQLiteRegionalKeyOwnerSurvivesRestartAndDeletionScheduling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key-owner.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repo := backend.New(db)
	at := time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC)
	sc := domain.StorageScope{Partition: "aws", AccountID: "111122223333", Region: "us-west-2"}
	claim := owner.KeyResourceOwner{StackID: "stack", LogicalID: "Replica", Token: "incarnation-a"}
	key := domain.KeyRecord{ID: "mrk-0123456789abcdef0123456789abcdef", ARN: "arn:aws:kms:us-west-2:111122223333:key/mrk-0123456789abcdef0123456789abcdef", Created: at, AvailableAt: at, Manager: "CUSTOMER", State: "Enabled", Policy: "{}", Owner: claim}
	if err := repo.Transact(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutKeySet(domain.KeyOwner{Partition: sc.Partition, AccountID: sc.AccountID}, domain.KeySetRecord{ID: key.ID, Spec: "SYMMETRIC_DEFAULT", Usage: "ENCRYPT_DECRYPT", Origin: "AWS_KMS", MultiRegion: true, PrimaryRegion: "us-east-1", ReplicaRegions: []string{sc.Region}}); err != nil {
			return err
		}
		return tx.PutKey(sc, key)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo = backend.New(db)
	if err := repo.Transact(t.Context(), func(tx domain.Transaction) error {
		keys, err := tx.Keys(sc)
		if err != nil {
			return err
		}
		if len(keys) != 1 || keys[0].Owner != claim {
			t.Fatalf("restart lost the actual regional key claim: %+v", keys)
		}
		deletion := at.Add(7 * 24 * time.Hour)
		keys[0].State, keys[0].Deletion = "PendingDeletion", &deletion
		return tx.PutKey(sc, keys[0])
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.View(t.Context(), func(reader domain.Reader) error {
		keys, err := reader.Keys(sc)
		if err == nil && (len(keys) != 1 || keys[0].Owner != claim || keys[0].State != "PendingDeletion") {
			t.Fatalf("deletion scheduling released the live regional key incarnation: %+v", keys)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteKeyOwnerMigrationDoesNotAdoptLegacyKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-key-owner.sqlite")
	db := awstest.HistoricalSQLite(t, path, "../schema", 336, "", nil)
	at := time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC)
	if _, err := db.ExecContext(t.Context(), `INSERT INTO kms_key_sets
		(partition, account, key_id, spec, usage, origin, current_material_id, pending_material_id,
		rotation_enabled, rotation_period_days, rotation_next, rotation_started, multi_region, primary_region)
		VALUES ('aws', '111122223333', 'legacy-key', 'SYMMETRIC_DEFAULT', 'ENCRYPT_DECRYPT', 'AWS_KMS',
		'', '', false, 0, ?, ?, false, 'us-west-2')`, at, at); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO kms_keys
		(partition, account, region, key_id, arn, description, manager, state, created, available_at, pending_deletion_days, policy)
		VALUES ('aws', '111122223333', 'us-west-2', 'legacy-key', 'legacy-arn', '', 'CUSTOMER', 'Enabled', ?, ?, 0, '{}')`, at, at); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := backend.New(db)
	if err := repo.View(t.Context(), func(reader domain.Reader) error {
		keys, err := reader.Keys(domain.StorageScope{Partition: "aws", AccountID: "111122223333", Region: "us-west-2"})
		if err == nil && (len(keys) != 1 || keys[0].Owner != (owner.KeyResourceOwner{}) || !keys[0].Created.Equal(at)) {
			t.Fatalf("migration adopted or recreated a legacy key: %+v", keys)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
