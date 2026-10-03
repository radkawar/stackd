package athena_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"stackd/journal"
	domain "stackd/storage/athena"
	journaldb "stackd/storage/sqlite/journal"
)

func TestQueryAndJournalRollbackWithNestedWritesAndAttempts(t *testing.T) {
	s := openStore(t)
	events := journaldb.New(s.db)
	query := retainedQuery()
	appendEvent := func(ctx context.Context, id string) error {
		return events.AppendAPICallCompleted(ctx, journal.Envelope{At: time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC), Partition: query.Key.Partition, AccountID: query.Key.AccountID, Region: query.Key.Region, RequestID: id}, journal.APICallCompleted{EventID: id, EventSource: "athena.amazonaws.com", EventName: "StartQueryExecution", Category: journal.CategoryManagement})
	}
	if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutQuery(query); err != nil {
			return err
		}
		return appendEvent(tx.Context(), "accepted")
	}); err != nil {
		t.Fatal(err)
	}
	// The journal's duplicate-event rejection must roll back the preceding query
	// replacement, including its rewritten caller and result-metadata children.
	changed := query
	changed.Columns = nil
	changed.Caller.SessionContext = nil
	changed.Version++
	if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutQuery(changed); err != nil {
			return err
		}
		return appendEvent(tx.Context(), "accepted")
	}); err == nil {
		t.Fatal("duplicate journal event committed a query mutation")
	}
	rejected := errors.New("rejected child command")
	if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutQuery(changed); err != nil {
			return err
		}
		err := s.repo.Update(tx.Context(), func(child domain.Transaction) error {
			if err := child.PutCatalog(domain.CatalogRecord{Key: key("aborted-catalog")}); err != nil {
				return err
			}
			if err := appendEvent(child.Context(), "aborted-nested"); err != nil {
				return err
			}
			return rejected
		})
		if !errors.Is(err, rejected) {
			return err
		}
		return nil // An ordinary nested error still poisons its enclosing owner.
	}); !errors.Is(err, rejected) {
		t.Fatalf("nested rejection was swallowed: %v", err)
	}
	if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
		err := s.repo.Attempt(tx.Context(), func(child domain.Transaction) error {
			if err := child.PutQuery(changed); err != nil {
				return err
			}
			if err := child.PutCatalog(domain.CatalogRecord{Key: key("attempt-catalog")}); err != nil {
				return err
			}
			if err := appendEvent(child.Context(), "rejected-attempt"); err != nil {
				return err
			}
			return rejected
		})
		if !errors.Is(err, rejected) {
			return err
		}
		if err := tx.PutWorkGroup(domain.WorkGroupRecord{Key: key("surviving-workgroup")}); err != nil {
			return err
		}
		return appendEvent(tx.Context(), "surviving-owner")
	}); err != nil {
		t.Fatal(err)
	}
	s.reopen(t)
	events = journaldb.New(s.db)
	if err := s.repo.View(t.Context(), func(r domain.Reader) error {
		got, err := r.Query(query.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, query) {
			t.Fatalf("failed transaction changed retained query or children: %#v", got)
		}
		for _, name := range []string{"aborted-catalog", "attempt-catalog"} {
			if _, err := r.Catalog(key(name)); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("rolled back %s remains: %v", name, err)
			}
		}
		_, err = r.WorkGroup(key("surviving-workgroup"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got, err := events.Read(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(got))
	for _, event := range got {
		if event.APICallCompleted != nil {
			ids = append(ids, event.APICallCompleted.EventID)
		}
	}
	if !reflect.DeepEqual(ids, []string{"accepted", "surviving-owner"}) {
		t.Fatalf("events escaped their resource transaction: %v", ids)
	}
}
