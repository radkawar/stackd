package kms_test

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/internal/awstest"
	domain "stackd/storage/kms"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/kms"
)

func TestSQLiteRetainsScopedMaterialAndRegionalRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := backend.New(db)
	at := time.Date(2030, 1, 2, 3, 4, 5, 123456789, time.UTC)
	set := domain.KeySetRecord{ID: "same-id", Spec: "SYMMETRIC_DEFAULT", Usage: "ENCRYPT_DECRYPT", Origin: "EXTERNAL", CurrentMaterialID: "current", PendingMaterialID: "pending", MultiRegion: true, PrimaryRegion: "us-east-1", ReplicaRegions: []string{"us-west-2", "eu-west-1"}, Rotation: domain.RotationState{Enabled: true, PeriodInDays: 90, Next: at.Add(time.Hour), OnDemandStarted: at}, Materials: []domain.KeyMaterialRecord{
		{ID: "current", Material: []byte{1, 2, 3}, RotationDate: at, RotationType: "ON_DEMAND", Description: "current"}, {ID: "pending", Material: []byte{4, 5, 6}, Description: "pending"}, {ID: "deleted"},
	}}
	key := domain.KeyRecord{ID: set.ID, ARN: "regional-arn", Description: "regional", Manager: "CUSTOMER", State: "PendingDeletion", Created: at, Deletion: &at, AvailableAt: at.Add(time.Second), PendingDeletionWindowInDays: 7, Policy: "policy", Principals: []domain.PrincipalBinding{{Reference: "arn", ID: "principal"}}, Tags: []domain.TagRecord{{Key: "team", Value: "owner"}},
		Imports:          []domain.ImportedMaterialRecord{{ID: "current", ValidTo: &at}, {ID: "pending"}},
		ImportParameters: []domain.ImportParametersRecord{{Token: []byte{1, 2}, PrivateKey: []byte{3, 4}, Algorithm: "RSAES_OAEP_SHA_256", ValidTo: at.Add(24 * time.Hour)}},
		Grants:           []domain.GrantRecord{{ID: "grant", Name: "name", Grantee: "grantee", GranteeID: "grantee-id", Retiring: "retiring", RetiringID: "retiring-id", Issuer: "issuer", Created: at, Operations: []string{"Decrypt", "Encrypt"}, Tokens: []string{"token-b", "token-a"}, EncryptionContextEquals: []domain.TagRecord{{Key: "purpose", Value: "test"}}, EncryptionContextSubset: []domain.TagRecord{{Key: "team", Value: "owner"}}}},
	}
	owners := []domain.KeyOwner{{Partition: "aws", AccountID: "111111111111"}, {Partition: "aws", AccountID: "222222222222"}, {Partition: "aws-cn", AccountID: "111111111111"}}
	for i, owner := range owners {
		if err := repo.Transact(t.Context(), func(tx domain.Transaction) error {
			copy := set
			copy.Materials = append([]domain.KeyMaterialRecord(nil), set.Materials...)
			copy.Materials[0].Material = []byte{byte(i), 2, 3}
			if err := tx.PutKeySet(owner, copy); err != nil {
				return err
			}
			for _, region := range []string{"us-east-1", "us-west-2"} {
				sc := domain.StorageScope{Partition: owner.Partition, AccountID: owner.AccountID, Region: region}
				if err := tx.PutKey(sc, key); err != nil {
					return err
				}
				if err := tx.PutAlias(sc, domain.AliasRecord{Name: "alias/retained", KeyID: set.ID, Created: at, Updated: at.Add(time.Minute), Owner: domain.AliasOwner{StackID: owner.AccountID + ":" + region, LogicalID: "Alias", Token: owner.Partition}}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repo = backend.New(db)
	for i, owner := range owners {
		if err := repo.View(t.Context(), func(tx domain.Reader) error {
			got, err := tx.KeySet(owner, set.ID)
			if err != nil {
				return err
			}
			want := set
			want.Materials = append([]domain.KeyMaterialRecord(nil), set.Materials...)
			want.Materials[0].Material = []byte{byte(i), 2, 3}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("material history or owner isolation lost", got)
			}
			clear(got.Materials[0].Material)
			for _, region := range []string{"us-east-1", "us-west-2"} {
				sc := domain.StorageScope{Partition: owner.Partition, AccountID: owner.AccountID, Region: region}
				keys, err := tx.Keys(sc)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(keys, []domain.KeyRecord{key}) {
					t.Fatal("regional record round trip lost state", keys)
				}
				aliases, err := tx.Aliases(sc)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(aliases, []domain.AliasRecord{{Name: "alias/retained", KeyID: set.ID, Created: at, Updated: at.Add(time.Minute), Owner: domain.AliasOwner{StackID: owner.AccountID + ":" + region, LogicalID: "Alias", Token: owner.Partition}}}) {
					t.Fatal("alias round trip lost state", aliases)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	owner := owners[0]
	var escaped domain.Transaction
	if err := repo.Transact(t.Context(), func(tx domain.Transaction) error {
		escaped = tx
		got, err := tx.KeySet(owner, set.ID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got.Materials[0].Material, []byte{0, 2, 3}) {
			t.Fatal("caller mutated stored material")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := escaped.KeySet(owner, set.ID); err == nil {
		t.Fatal("escaped key reader remains usable", err)
	}
	if err := escaped.PutKeySet(owner, set); err == nil {
		t.Fatal("escaped key writer remains usable", err)
	}
	// Failing a regional write rolls back material changes staged earlier in
	// the same callback, which is how multi-Region KMS operations commit.
	abort := errors.New("regional write failed")
	if err := repo.Transact(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutKeySet(owner, domain.KeySetRecord{ID: set.ID}); err != nil {
			return err
		}
		if err := tx.DeleteKey(domain.StorageScope{Partition: owner.Partition, AccountID: owner.AccountID, Region: "us-west-2"}, set.ID); err != nil {
			return err
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if err := repo.Transact(t.Context(), func(tx domain.Transaction) error {
		got, err := tx.KeySet(owner, set.ID)
		if err != nil {
			return err
		}
		if len(got.Materials) != 3 {
			t.Fatal("failed transaction changed material history")
		}
		for _, region := range []string{"us-east-1", "us-west-2"} {
			sc := domain.StorageScope{Partition: owner.Partition, AccountID: owner.AccountID, Region: region}
			if err := tx.DeleteKey(sc, set.ID); err != nil {
				return err
			}
			aliases, err := tx.Aliases(sc)
			if err != nil {
				return err
			}
			if len(aliases) != 0 {
				t.Fatal("deleted key retained aliases")
			}
		}
		if err := tx.DeleteKeySet(owner, set.ID); err != nil {
			return err
		}
		_, err = tx.KeySet(owner, set.ID)
		if !errors.Is(err, domain.ErrKeySetNotFound) {
			t.Fatal("deleted material remains", err)
		}
		_, err = tx.KeySet(owners[1], set.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteAliasOwnerMigrationLeavesLegacyUnowned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db := awstest.HistoricalSQLite(t, path, "../schema", 296, "", nil)
	at := time.Date(2030, 1, 2, 3, 4, 5, 123456789, time.UTC)
	// Seed the historical columns rather than using today's alias writer.
	if _, err := db.ExecContext(t.Context(), `INSERT INTO kms_key_sets
		(partition, account, key_id, spec, usage, origin, current_material_id, pending_material_id,
		rotation_enabled, rotation_period_days, rotation_next, rotation_started, multi_region, primary_region)
		VALUES ('aws', '111122223333', 'legacy-key', 'SYMMETRIC_DEFAULT', 'ENCRYPT_DECRYPT', 'AWS_KMS',
		'', '', false, 0, ?, ?, false, 'us-east-1')`, at, at); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO kms_keys
		(partition, account, region, key_id, arn, description, manager, state, created, available_at, pending_deletion_days, policy)
		VALUES ('aws', '111122223333', 'us-east-1', 'legacy-key', 'legacy-arn', '', 'CUSTOMER', 'Enabled', ?, ?, 0, '{}')`, at, at); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO kms_aliases
		(partition, account, region, name, key_id, created, updated)
		VALUES ('aws', '111122223333', 'us-east-1', 'alias/legacy', 'legacy-key', ?, ?)`, at, at.Add(time.Minute)); err != nil {
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
	sc := domain.StorageScope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}
	if err := repo.View(t.Context(), func(tx domain.Reader) error {
		got, err := tx.Aliases(sc)
		if err != nil {
			return err
		}
		want := []domain.AliasRecord{{Name: "alias/legacy", KeyID: "legacy-key", Created: at, Updated: at.Add(time.Minute)}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("migration changed legacy alias or invented ownership: %+v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
