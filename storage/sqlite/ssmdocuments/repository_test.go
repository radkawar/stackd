package ssmdocuments_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"time"

	"github.com/google/uuid"
	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	service "stackd/internal/services/ssmdocuments"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/ssmdocuments"
	domain "stackd/storage/ssmdocuments"
)

type unavailableRecorder struct{}

func (unavailableRecorder) Record(context.Context, journal.Envelope, journal.APICallCompleted) error {
	return errors.New("journal unavailable")
}
func TestDocumentMutationRollsBackWhenJournalFails(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var repository domain.Repository
			if kind == "memory" {
				repository = domain.NewMemory(memory.NewDomain())
			} else {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "documents.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				repository = backend.New(db)
			}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111122223333", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111122223333:root", PrincipalID: "111122223333"})
			s := service.New(service.Config{Repository: repository, Recorder: unavailableRecorder{}})
			defer s.Close()
			request, err := api.DecodeRequest("CreateDocument", awsapi.Request{JSON: []byte(`{"Name":"RollbackCommand","Content":"{\"schemaVersion\":\"2.2\",\"mainSteps\":[{\"name\":\"shell\",\"action\":\"aws:runShellScript\",\"inputs\":{\"runCommand\":[\"exit 0\"]}}]}"}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, rejected := s.ExecuteCommand(ctx, request); rejected == nil || rejected.Code != "InternalServerError" {
				t.Fatalf("journal failure admitted mutation: %v", rejected)
			}
			key := domain.Key{Scope: domain.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}, Name: "RollbackCommand"}
			if err = repository.View(ctx, func(r domain.Reader) error {
				_, err := r.Document(key)
				if !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("document survived rejected transaction: %v", err)
				}
				if _, err := r.NextActivation(); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("activation survived rejected transaction: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPendingDocumentVersionsSurviveReopen(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "pending.db")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	repository := backend.New(db)
	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	manual := clock.NewManual(now)
	key := domain.Key{Scope: domain.Scope{Partition: "aws", AccountID: "000000000000", Region: "us-east-1"}, Name: "RestartDocument"}
	id := uuid.NewString()
	if err := repository.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutDocument(domain.Record{Key: key, Type: "Command", DocumentID: id, DefaultVersion: 1, LatestVersion: 2, NextVersion: 3}); err != nil {
			return err
		}
		for i, status := range []string{"Creating", "Updating"} {
			v := domain.Version{Key: domain.VersionKey{Document: key, Version: int64(i + 1)}, Content: "immutable version source", Format: "JSON", Created: now, Status: status, ReadyAt: now.Add(time.Duration(i) * time.Second)}
			if err := tx.InsertVersion(v); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository = backend.New(db)
	s := service.New(service.Config{Repository: repository, Clock: manual})
	defer s.Close()
	assertState := func(first, second string) {
		t.Helper()
		if err := repository.View(ctx, func(r domain.Reader) error {
			record, err := r.Document(key)
			if err != nil {
				return err
			}
			if record.DocumentID != id || record.DefaultVersion != 1 || record.LatestVersion != 2 {
				t.Fatalf("identity or version pointers changed: %+v", record)
			}
			versions, err := r.Versions(key)
			if err != nil {
				return err
			}
			if len(versions) != 2 || versions[0].Status != first || versions[1].Status != second || versions[1].Content != "immutable version source" {
				t.Fatalf("reopened lifecycle: %+v", versions)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertState("Creating", "Updating")
	if _, err := s.JobDriver().RunDue(ctx, 10); err != nil {
		t.Fatal(err)
	}
	assertState("Active", "Updating")
	manual.Advance(time.Second)
	if _, err := s.JobDriver().RunDue(ctx, 10); err != nil {
		t.Fatal(err)
	}
	assertState("Active", "Active")
	if err := repository.View(ctx, func(r domain.Reader) error {
		_, err := r.NextActivation()
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("completed activation remained pending: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
