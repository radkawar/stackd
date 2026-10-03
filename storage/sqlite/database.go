// Package sqlite owns SQLite connection setup, schema migration and transaction
// lifetime. Service adapters own their tables and SQLC queries.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"stackd/storage/sqlite/schema"

	_ "modernc.org/sqlite" // Register the database/sql driver.
)

// Open opens an on-disk database and applies the current service schemas. The
// caller owns Close. One active stack owns a database, as with storage.Backends.
// The connection pool serializes callbacks; waiting callers remain cancellable.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("SQLite database path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	query := url.Values{"_txlock": {"immediate"}, "_pragma": {"foreign_keys(1)", "busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)"}}
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: query.Encode()}
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := Transact(ctx, db, false, func(ctx context.Context, tx *sql.Tx) error {
		var version int
		if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			return err
		}
		if version == 0 {
			// Empty databases need the current schema, not historical rewrites.
			// The generated bootstrap includes the migrations' seed rows/version.
			if _, err := tx.ExecContext(ctx, bootstrapSchema); err != nil {
				return err
			}
			version = bootstrapVersion
		}
		_, err := schema.Apply(ctx, tx, version)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open SQLite state: %w", err)
	}
	return db, nil
}
