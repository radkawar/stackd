package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"stackd/internal/awstest"
	"stackd/internal/identity"
	"stackd/journal"
	"stackd/storage/sqlite"
	sqljournal "stackd/storage/sqlite/journal"
)

func TestSQLiteAccountSelectionReopenAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	check := func(want string) {
		t.Helper()
		got, err := sqlite.ResolveAccountID(t.Context(), db, "")
		if err != nil || got != want {
			t.Fatalf("saved account = %q, %v; want %q", got, err, want)
		}
	}
	check(identity.DefaultAccountID)
	const override = "820493716052"
	if got, err := sqlite.ResolveAccountID(t.Context(), db, override); err != nil || got != override {
		t.Fatalf("override = %q, %v", got, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	check(override)
	abort := errors.New("abort identity change")
	err = sqlite.Transact(t.Context(), db, false, func(ctx context.Context, _ *sql.Tx) error {
		if _, err := sqlite.ResolveAccountID(ctx, db, "000000000000"); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	check(override)
	if _, err := sqlite.ResolveAccountID(t.Context(), db, "invalid"); err == nil {
		t.Fatal("accepted invalid account")
	}
	check(override)
}

func TestSQLiteAccountSelectionLegacyUpgrade(t *testing.T) {
	// Schema versions count ordered files, including duplicate numeric prefixes.
	// Retain every migration through 405, stopping before account selection.
	files, err := filepath.Glob("schema/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	version := slices.Index(files, filepath.Join("schema", "406_instance_identity.sql"))
	if version < 0 {
		t.Fatal("instance identity migration not found")
	}
	for _, explicit := range []string{"", "820493716052"} {
		t.Run("override="+explicit, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "legacy.sqlite")
			legacy := awstest.HistoricalSQLite(t, path, "schema", version, "", nil)
			// A pre-upgrade ARN belongs to the old account and must not be rewritten.
			account := explicit
			if account == "" {
				account = "000000000000"
			}
			arn := "arn:aws:iam::" + account + ":role/retained"
			envelope := journal.Envelope{Partition: "aws", AccountID: account, Region: "us-east-1", RequestID: "retained", ActorARN: arn}
			change := journal.AccessKeyChanged{Action: journal.AccessKeyCreated, AccessKeyID: "AKIARETAINED", PrincipalARN: arn, Status: "Active"}
			if err := sqljournal.New(legacy).AppendAccessKeyChanged(t.Context(), envelope, change); err != nil {
				t.Fatal(err)
			}
			if err := legacy.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sqlite.Open(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			got, err := sqlite.ResolveAccountID(t.Context(), db, explicit)
			if err != nil || got != account {
				t.Fatalf("upgraded account = %q, %v; want %q", got, err, account)
			}
			rows, err := sqljournal.New(db).Read(t.Context(), 0, 100)
			if err != nil || len(rows) != 1 || rows[0].ActorARN != arn || rows[0].AccountID != account || rows[0].AccessKeyChanged.PrincipalARN != arn {
				t.Fatalf("upgrade changed retained account event: %+v, %v", rows, err)
			}
		})
	}
}
