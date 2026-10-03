package opensearch_test

import (
	"errors"
	"maps"
	"path/filepath"
	"testing"
	"time"

	domain "stackd/storage/opensearch"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/opensearch"
)

func TestControllerIntentSurvivesRollbackAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opensearch.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := backend.New(db)
	key := domain.Key{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "retained"}
	created := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	original := domain.Domain{
		Key: key, Incarnation: "1902276f-cb54-4eaa-8cfa-30f82af78c3e", EngineVersion: "OpenSearch_2.19",
		Status: "updating", NativeEndpoint: "http://127.0.0.1:19200", LastError: "native engine unavailable",
		AccessPolicy: `{"Version":"2012-10-17","Statement":[]}`,
		InstanceType: "m5.large.search", InstanceCount: 1,
		AdvancedOptions:  map[string]string{"rest.action.multi.allow_explicit_index": "true"},
		PolicyPrincipals: map[string]string{"arn:aws:iam::111111111111:role/reader": "AROARETAINED"},
		Tags:             map[string]string{"owner": "retained"},
		Created:          created, Updated: created.Add(123 * time.Nanosecond), Due: time.Unix(0, 0).UTC(), Version: 11, ConfigVersion: 5,
	}
	if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutDomain(original) }); err != nil {
		t.Fatal(err)
	}
	rejected := errors.New("controller transition rejected")
	if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
		changed, err := tx.Domain(key)
		if err != nil {
			return err
		}
		changed.Version++
		changed.ConfigVersion++
		changed.Due = time.Time{}
		changed.LastError = ""
		changed.Status = "active"
		changed.AdvancedOptions = nil
		changed.PolicyPrincipals = nil
		changed.Tags = map[string]string{"owner": "not-committed"}
		if err := tx.PutDomain(changed); err != nil {
			return err
		}
		return rejected
	}); !errors.Is(err, rejected) {
		t.Fatalf("rollback result: %v", err)
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
		got, err := r.Domain(key)
		if err != nil {
			return err
		}
		if got.Incarnation != original.Incarnation || got.Version != original.Version || got.ConfigVersion != original.ConfigVersion || got.Status != original.Status || got.LastError != original.LastError || got.NativeEndpoint != original.NativeEndpoint {
			t.Fatalf("controller intent lost on restart: %#v", got)
		}
		if !got.Created.Equal(original.Created) || !got.Updated.Equal(original.Updated) || !got.Due.Equal(original.Due) || got.Due.IsZero() {
			t.Fatalf("retained timestamps lost precision or epoch identity: %#v", got)
		}
		if !maps.Equal(got.AdvancedOptions, original.AdvancedOptions) || !maps.Equal(got.PolicyPrincipals, original.PolicyPrincipals) || !maps.Equal(got.Tags, original.Tags) {
			t.Fatalf("child rows escaped rollback or restart: %#v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
