package lambda_test

import (
	"errors"
	"path/filepath"
	"testing"

	runtime "stackd/compute/lambda"
	"stackd/storage/lambda"
	"stackd/storage/sqlite"
	sqllambda "stackd/storage/sqlite/lambda"
)

func TestLoggingCandidatePromotionAndPublicationSurviveSQLiteReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logging.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := sqllambda.New(db)
	active := deployment()
	active.LogGroup = "application/active"
	active.Logging = runtime.LoggingConfig{Format: "JSON", ApplicationLevel: "INFO", SystemLevel: "DEBUG"}
	published := active
	published.Version = 1
	candidate := active
	candidate.LogGroup = "application/candidate"
	candidate.Logging = runtime.LoggingConfig{Format: "JSON", ApplicationLevel: "ERROR", SystemLevel: "WARN"}
	if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
		if err := tx.PutFunction(active); err != nil {
			return err
		}
		if _, err := tx.AllocateFunctionVersion(active.Key); err != nil {
			return err
		}
		if err := tx.PutFunctionVersion(published); err != nil {
			return err
		}
		return tx.PutPendingFunction(candidate)
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
	repo = sqllambda.New(db)
	check := func(activeGroup, pendingGroup string) {
		t.Helper()
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			current, err := r.Function(active.Key)
			if err != nil {
				return err
			}
			pending, err := r.PendingFunction(active.Key)
			if err != nil {
				return err
			}
			snapshot, err := r.FunctionVersion(lambda.FunctionVersionKey{FunctionKey: active.Key, Version: 1})
			if err != nil {
				return err
			}
			if current.LogGroup != activeGroup || pending.LogGroup != pendingGroup || snapshot.LogGroup != published.LogGroup {
				t.Fatalf("deployment destinations leaked between slots: active=%q pending=%q published=%q", current.LogGroup, pending.LogGroup, snapshot.LogGroup)
			}
			expected := map[string]runtime.LoggingConfig{
				"application/active":    active.Logging,
				"application/candidate": {Format: "JSON", ApplicationLevel: "ERROR", SystemLevel: "WARN"},
				"":                      {Format: "Text"},
			}
			if current.Logging != expected[activeGroup] || pending.Logging != expected[pendingGroup] || snapshot.Logging != published.Logging {
				t.Fatalf("logging controls leaked across promotion/publication: active=%+v pending=%+v published=%+v", current.Logging, pending.Logging, snapshot.Logging)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check(active.LogGroup, candidate.LogGroup)
	abort := errors.New("abort promotion")
	if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
		if err := tx.PutFunction(candidate); err != nil {
			return err
		}
		if err := tx.DeletePendingFunction(candidate.Key); err != nil {
			return err
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatalf("promotion rollback: %v", err)
	}
	check(active.LogGroup, candidate.LogGroup)
	if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
		if err := tx.PutFunction(candidate); err != nil {
			return err
		}
		// A pending reset to the derived default must not alter either the
		// newly active custom destination or the immutable published version.
		candidate.LogGroup = ""
		candidate.Logging = runtime.LoggingConfig{Format: "Text"}
		return tx.PutPendingFunction(candidate)
	}); err != nil {
		t.Fatal(err)
	}
	check("application/candidate", "")
}
