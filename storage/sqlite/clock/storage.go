// Package clock stores the instance's manual service time in SQLite.
package clock

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"stackd/storage/sqlite"
	"stackd/storage/sqlite/clock/internal/sqlcgen"
)

// Storage uses the same database as the service repositories. Its owner closes
// the stack and finishes clock advances before closing the database.
type Storage struct{ db *sql.DB }

func New(db *sql.DB) *Storage { return &Storage{db: db} }

func (s *Storage) Initialize(ctx context.Context, initial *time.Time) (time.Time, bool, error) {
	var instant time.Time
	var found bool
	err := sqlite.TransactOwned(ctx, s.db, initial == nil, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		var err error
		instant, err = q.CurrentTime(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			if initial == nil {
				return nil
			}
			instant = *initial
			err = q.InitializeTime(ctx, instant)
		}
		found = err == nil
		return err
	})
	return instant, found && err == nil, err
}

func (s *Storage) SetTime(ctx context.Context, instant time.Time) error {
	return sqlite.TransactOwned(ctx, s.db, false, func(ctx context.Context, tx *sql.Tx) error {
		return sqlcgen.New(tx).SetTime(ctx, instant)
	})
}
