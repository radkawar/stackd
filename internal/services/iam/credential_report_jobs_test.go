package iam

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"stackd/clock"
)

func TestCredentialReportJobFencesReplacedGeneration(t *testing.T) {
	ctx := t.Context()
	repository := NewMemoryRepository(nil)
	scope := Scope{Partition: "aws", AccountID: "123456789012"}
	epoch := time.Time{}
	s := NewWithConfig(Config{Repository: repository, Clock: clock.NewManual(epoch)})
	t.Cleanup(func() { _ = s.Close() })
	put := func(generation uint64) {
		t.Helper()
		if err := repository.Update(ctx, func(tx WriteTx) error {
			if err := tx.PutAccountMetadata(scope, AccountMetadata{CreatedAt: epoch}); err != nil {
				return err
			}
			return tx.PutCredentialReport(scope, CredentialReportRecord{Generation: generation, State: CredentialReportPending, RequestedAt: epoch})
		}); err != nil {
			t.Fatal(err)
		}
	}
	put(1)
	source := credentialReportJobs{s}
	stale, found, err := source.Next(ctx)
	if err != nil || !found {
		t.Fatal("missing first job", err)
	}
	put(2)
	if err := source.Run(ctx, stale); err != nil {
		t.Fatal(err)
	}
	assert := func(state CredentialReportState) {
		t.Helper()
		if err := repository.View(ctx, func(tx ReadTx) error {
			report, err := tx.CredentialReport(scope)
			if err == nil && (report.Generation != 2 || report.State != state) {
				t.Fatalf("stale worker changed replacement: %+v", report)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	assert(CredentialReportPending)
	result, err := s.RunDueJobs(ctx, 1)
	if err != nil || result.Processed != 1 {
		t.Fatal("replacement was not drainable", result, err)
	}
	assert(CredentialReportComplete)
	if err := source.Run(ctx, stale); err != nil {
		t.Fatal(err)
	}
	assert(CredentialReportComplete)
}

func TestCredentialReportRepositoryDetachmentAndRollback(t *testing.T) {
	repository := NewMemoryRepository(nil)
	scope := Scope{Partition: "aws", AccountID: "123456789012"}
	ctx := t.Context()
	content := []byte("original")
	if err := repository.Update(ctx, func(tx WriteTx) error {
		if err := tx.PutAccountMetadata(scope, AccountMetadata{}); err != nil {
			return err
		}
		return tx.PutCredentialReport(scope, CredentialReportRecord{Generation: 1, State: CredentialReportComplete, Content: content})
	}); err != nil {
		t.Fatal(err)
	}
	content[0] = '!'
	abort := errors.New("abort report replacement")
	if err := repository.Update(ctx, func(tx WriteTx) error {
		report, err := tx.CredentialReport(scope)
		if err != nil {
			return err
		}
		report.Content[0] = '?'
		if err := tx.PutCredentialReport(scope, report); err != nil {
			return err
		}
		if err := tx.PutAccountMetadata(scope, AccountMetadata{CreatedAt: time.Now()}); err != nil {
			return err
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatal(err)
	}
	var escaped ReadTx
	if err := repository.View(ctx, func(tx ReadTx) error {
		escaped = tx
		report, err := tx.CredentialReport(scope)
		if err != nil {
			return err
		}
		if !bytes.Equal(report.Content, []byte("original")) {
			t.Fatal("committed CSV aliased a writer", string(report.Content))
		}
		report.Content[0] = '#'
		again, err := tx.CredentialReport(scope)
		if err != nil || !bytes.Equal(again.Content, []byte("original")) {
			t.Fatal("committed CSV aliased a reader", err)
		}
		metadata, err := tx.AccountMetadata(scope)
		if err != nil || !metadata.CreatedAt.IsZero() {
			t.Fatal("metadata did not roll back", metadata, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := escaped.CredentialReport(scope); !errors.Is(err, ErrClosedTransaction) {
		t.Fatal("escaped report read succeeded", err)
	}
	if _, err := escaped.CredentialReportScopes(); !errors.Is(err, ErrClosedTransaction) {
		t.Fatal("escaped report scope read succeeded", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := repository.Update(canceled, func(tx WriteTx) error {
		return tx.PutCredentialReport(scope, CredentialReportRecord{})
	}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled repository write succeeded", err)
	}
}

func TestCredentialReportInvalidImportedJobDoesNotBlockOtherAccounts(t *testing.T) {
	repository := NewMemoryRepository(nil)
	s := NewWithConfig(Config{Repository: repository, Clock: clock.NewManual(time.Time{})})
	t.Cleanup(func() { _ = s.Close() })
	broken := Scope{Partition: "aws", AccountID: "111111111111"}
	healthy := Scope{Partition: "aws", AccountID: "222222222222"}
	if err := repository.Update(t.Context(), func(tx WriteTx) error {
		if err := tx.PutAccountMetadata(healthy, AccountMetadata{}); err != nil {
			return err
		}
		for _, scope := range []Scope{broken, healthy} {
			if err := tx.PutCredentialReport(scope, CredentialReportRecord{Generation: 1, State: CredentialReportPending}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	result, err := s.RunDueJobs(t.Context(), 2)
	if err != nil || result.Processed != 2 || result.More {
		t.Fatal("invalid import prevented account isolation", result, err)
	}
	if err := repository.View(t.Context(), func(tx ReadTx) error {
		for scope, want := range map[Scope]CredentialReportState{broken: CredentialReportFailed, healthy: CredentialReportComplete} {
			report, err := tx.CredentialReport(scope)
			if err != nil {
				return err
			}
			if report.State != want || report.State == CredentialReportFailed && len(report.Content) != 0 {
				t.Fatalf("account %s ended in %+v", scope.AccountID, report)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
