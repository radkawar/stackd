package opensearch_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"stackd/journal"
	"stackd/storage/memory"
	domain "stackd/storage/opensearch"
	"stackd/storage/sqlite"
	journaldb "stackd/storage/sqlite/journal"
	backend "stackd/storage/sqlite/opensearch"
)

func repositories(t *testing.T, fn func(*testing.T, domain.Repository, journal.Storage)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		d := memory.NewDomain()
		fn(t, domain.NewMemory(d), journal.NewMemory(d))
	})
	t.Run("sqlite", func(t *testing.T) {
		db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "opensearch.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		fn(t, backend.New(db), journaldb.New(db))
	})
}

func originalDomain() domain.Domain {
	return domain.Domain{
		Key:         domain.Key{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "search"},
		Incarnation: "ed36819f-a6ec-4945-91a5-5889bf411db2", EngineVersion: "OpenSearch_2.19",
		Status: "updating", NativeEndpoint: "http://127.0.0.1:19200", LastError: "connection refused",
		AccessPolicy: `{"Version":"2012-10-17","Statement":[]}`,
		InstanceType: "m5.large.search", InstanceCount: 1,
		AdvancedOptions:  map[string]string{"rest.action.multi.allow_explicit_index": "true"},
		PolicyPrincipals: map[string]string{"arn:aws:iam::111111111111:role/search": "AROAORIGINAL"},
		Tags:             map[string]string{"owner": "original"},
		Created:          time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC),
		Updated:          time.Date(2031, 2, 3, 4, 6, 7, 987654321, time.UTC),
		Due:              time.Unix(0, 0).UTC(), Version: 7, ConfigVersion: 3,
	}
}

func requireDomain(t *testing.T, r domain.Reader, want domain.Domain) {
	t.Helper()
	got, err := r.Domain(want.Key)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("domain mismatch:\n got %#v\nwant %#v", got, want)
	}
}

func requireCurrent(t *testing.T, repo domain.Repository, want domain.Domain) {
	t.Helper()
	if err := repo.View(t.Context(), func(r domain.Reader) error {
		requireDomain(t, r, want)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDomainMapsCannotMutateStoredIntent(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository, _ journal.Storage) {
		want := originalDomain()
		input := originalDomain()
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.PutDomain(input); err != nil {
				return err
			}
			input.AdvancedOptions["rest.action.multi.allow_explicit_index"] = "false"
			input.PolicyPrincipals["arn:aws:iam::111111111111:role/search"] = "AROAREPLACED"
			input.Tags["owner"] = "changed"
			requireDomain(t, tx, want)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r domain.Reader) error {
			one, err := r.Domain(want.Key)
			if err != nil {
				return err
			}
			scoped, err := r.Domains(want.Key.Scope)
			if err != nil {
				return err
			}
			all, err := r.AllDomains()
			if err != nil {
				return err
			}
			for _, v := range []domain.Domain{one, scoped[0], all[0]} {
				clear(v.AdvancedOptions)
				clear(v.PolicyPrincipals)
				clear(v.Tags)
			}
			requireDomain(t, r, want)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		requireCurrent(t, repo, want)
	})
}

func TestDomainAndJournalRollbackShareTransactionAndSavepoints(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository, events journal.Storage) {
		want := originalDomain()
		appendEvent := func(ctx context.Context, id string) error {
			return events.AppendAPICallCompleted(ctx,
				journal.Envelope{At: want.Created, Partition: want.Key.Partition, AccountID: want.Key.AccountID, Region: want.Key.Region},
				journal.APICallCompleted{EventID: id, EventSource: "es.amazonaws.com", EventName: "UpdateDomainConfig", Category: journal.CategoryManagement})
		}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.PutDomain(want); err != nil {
				return err
			}
			return appendEvent(tx.Context(), "original")
		}); err != nil {
			t.Fatal(err)
		}
		changed := originalDomain()
		changed.ConfigVersion++
		changed.Version++
		changed.Status = "active"
		changed.LastError = ""
		changed.Due = time.Time{}
		changed.AdvancedOptions = map[string]string{"indices.query.bool.max_clause_count": "2048"}
		changed.PolicyPrincipals = map[string]string{"arn:aws:iam::111111111111:role/other": "AROAOTHER"}
		changed.Tags = map[string]string{"team": "new"}
		rejected := errors.New("reject command")
		stage := func(tx domain.Transaction) error {
			if err := tx.PutDomain(changed); err != nil {
				return err
			}
			return appendEvent(tx.Context(), "changed")
		}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := stage(tx); err != nil {
				return err
			}
			return rejected
		}); !errors.Is(err, rejected) {
			t.Fatalf("rollback result: %v", err)
		}
		requireCurrent(t, repo, want)
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			err := repo.Attempt(tx.Context(), func(child domain.Transaction) error {
				if err := stage(child); err != nil {
					return err
				}
				return rejected
			})
			if !errors.Is(err, rejected) {
				t.Fatalf("savepoint result: %v", err)
			}
			requireDomain(t, tx, want)
			if err := repo.Attempt(tx.Context(), stage); err != nil {
				return err
			}
			requireDomain(t, tx, changed)
			return rejected
		}); !errors.Is(err, rejected) {
			t.Fatalf("outer rollback result: %v", err)
		}
		requireCurrent(t, repo, want)
		gotEvents, err := events.Read(t.Context(), 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(gotEvents) != 1 || gotEvents[0].APICallCompleted.EventID != "original" {
			t.Fatalf("rolled-back events escaped: %#v", gotEvents)
		}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			return repo.Attempt(tx.Context(), stage)
		}); err != nil {
			t.Fatal(err)
		}
		requireCurrent(t, repo, changed)
		gotEvents, err = events.Read(t.Context(), 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(gotEvents) != 2 || gotEvents[1].APICallCompleted.EventID != "changed" {
			t.Fatalf("accepted event missing: %#v", gotEvents)
		}
	})
}

func TestDomainScopeOrderingMissingAndNameReuse(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository, _ journal.Storage) {
		original := originalDomain()
		base := original.Key
		keys := []domain.Key{
			{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "alpha"},
			base,
			{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-west-2"}, Name: "alpha"},
			{Scope: domain.Scope{Partition: "aws", AccountID: "222222222222", Region: "us-east-1"}, Name: "alpha"},
			{Scope: domain.Scope{Partition: "aws-cn", AccountID: "111111111111", Region: "cn-north-1"}, Name: "alpha"},
		}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			for _, i := range []int{3, 1, 4, 0, 2} {
				v := originalDomain()
				v.Key = keys[i]
				if err := tx.PutDomain(v); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r domain.Reader) error {
			all, err := r.AllDomains()
			if err != nil {
				return err
			}
			gotKeys := make([]domain.Key, len(all))
			for i, v := range all {
				gotKeys[i] = v.Key
			}
			if !slices.Equal(gotKeys, keys) {
				t.Fatalf("global domain ordering: %v, want %v", gotKeys, keys)
			}
			scoped, err := r.Domains(base.Scope)
			if err != nil {
				return err
			}
			gotKeys = gotKeys[:0]
			for _, v := range scoped {
				gotKeys = append(gotKeys, v.Key)
			}
			if !slices.Equal(gotKeys, keys[:2]) {
				t.Fatalf("scoped domain ordering: %v, want %v", gotKeys, keys[:2])
			}
			missing := base
			missing.Region = "eu-west-1"
			if _, err := r.Domain(missing); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("missing scoped domain: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.DeleteDomain(base); err != nil {
				return err
			}
			if _, err := tx.Domain(base); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("deleted domain: %v", err)
			}
			return tx.PutDomain(domain.Domain{Key: base, Incarnation: "93c811e2-304a-4a6a-bb79-aec0958c3e4c", Status: "creating", Version: 1})
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r domain.Reader) error {
			got, err := r.Domain(base)
			if err != nil {
				return err
			}
			if got.Incarnation == original.Incarnation || got.Version != 1 || got.Status != "creating" || len(got.AdvancedOptions) != 0 || len(got.Tags) != 0 || len(got.PolicyPrincipals) != 0 || got.NativeEndpoint != "" || !got.Due.IsZero() {
				t.Fatalf("name reuse inherited old incarnation state: %#v", got)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
