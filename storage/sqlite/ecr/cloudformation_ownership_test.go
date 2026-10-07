package ecr_test

import (
	"errors"
	"path/filepath"
	api "stackd/internal/awsapi/ecr"
	domain "stackd/storage/ecr"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/ecr"
	"testing"
)

func TestRegistryResourceIncarnationsSurviveRestartAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repository := backend.New(db)
	scope := domain.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	original := domain.RegistryRecord{Scope: scope, PolicyOwnership: "policy-first", ReplicationOwnership: "replication-first", ScanningOwnership: "scanning-first", Scanning: api.RegistryScanningConfiguration{ScanType: new(api.ScanTypeBASIC)}, Replication: api.ReplicationConfiguration{Rules: api.ReplicationRuleList{}}}
	if err = repository.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutRegistry(original) }); err != nil {
		t.Fatal(err)
	}
	abort := errors.New("abort")
	if err = repository.Attempt(t.Context(), func(tx domain.Transaction) error {
		changed := original
		changed.PolicyOwnership, changed.ReplicationOwnership, changed.ScanningOwnership = "", "", ""
		if err := tx.PutRegistry(changed); err != nil {
			return err
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatalf("rollback error: %v", err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repository = backend.New(db)
	if err = repository.View(t.Context(), func(reader domain.Reader) error {
		r, err := reader.Registry(scope)
		if err != nil {
			return err
		}
		if r.PolicyOwnership != original.PolicyOwnership || r.ReplicationOwnership != original.ReplicationOwnership || r.ScanningOwnership != original.ScanningOwnership {
			t.Fatalf("restart lost resource incarnation metadata: %#v", r)
		}
		all, err := reader.AllRegistries()
		if err != nil {
			return err
		}
		if len(all) != 1 || all[0].ReplicationOwnership != original.ReplicationOwnership {
			t.Fatal("registry recovery list lost resource incarnation metadata")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryIncarnationSurvivesRestartAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repository.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repository := backend.New(db)
	key := domain.RepositoryKey{Scope: domain.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "owned"}
	original := domain.RepositoryRecord{Key: key, ARN: "arn:aws:ecr:us-east-1:123456789012:repository/owned", Mutability: "MUTABLE", EncryptionType: "AES256", Tags: map[string]string{"stackd:cloudformation:incarnation": "forged"}, Ownership: `["stack","Repository","first"]`}
	if err = repository.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutRepository(original) }); err != nil {
		t.Fatal(err)
	}
	abort := errors.New("abort")
	if err = repository.Attempt(t.Context(), func(tx domain.Transaction) error {
		changed := original
		changed.Ownership = ""
		if err := tx.PutRepository(changed); err != nil {
			return err
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatalf("rollback error: %v", err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repository = backend.New(db)
	if err = repository.View(t.Context(), func(reader domain.Reader) error {
		r, err := reader.Repository(key)
		if err != nil {
			return err
		}
		if r.Ownership != original.Ownership {
			t.Fatalf("restart lost private repository claim: %q", r.Ownership)
		}
		all, err := reader.AllRepositories()
		if err != nil {
			return err
		}
		if len(all) != 1 || all[0].Ownership != original.Ownership {
			t.Fatal("repository recovery list lost private claim")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
