// Package schema owns the ordered service migrations shared by runtime upgrades
// and fresh-database bootstrap generation.
package schema

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
)

//go:embed *.sql
var files embed.FS

// Apply runs migrations after version in the caller's transaction and returns
// the resulting version. The schema and user_version commit together.
func Apply(ctx context.Context, tx *sql.Tx, version int) (int, error) {
	migrations, err := files.ReadDir(".")
	if err != nil {
		return 0, err
	}
	if version < 0 || version > len(migrations) {
		return 0, fmt.Errorf("unsupported SQLite schema version %d", version)
	}
	for _, migration := range migrations[version:] {
		body, err := files.ReadFile(migration.Name())
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			return 0, fmt.Errorf("apply SQLite migration %s: %w", migration.Name(), err)
		}
	}
	if version != len(migrations) {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", len(migrations))); err != nil {
			return 0, err
		}
	}
	return len(migrations), nil
}
