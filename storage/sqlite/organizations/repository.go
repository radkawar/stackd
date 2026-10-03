// Package organizations stores the Organizations registry and policy graph in
// service-owned SQLite tables.
package organizations

import (
	"context"
	"database/sql"
	"errors"

	domain "stackd/storage/organizations"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/organizations/internal/sqlcgen"
)

// Repository joins related IAM and Account transactions on the same database.
// The caller owns the database and must close its stack first.
type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }

func (r *Repository) Partitions(ctx context.Context) ([]string, error) {
	var partitions []string
	err := sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		partitions, err = sqlcgen.New(tx).Partitions(ctx)
		return err
	})
	return partitions, err
}

func (r *Repository) Load(ctx context.Context, partition string) (domain.PartitionRecord, uint64, error) {
	var record domain.PartitionRecord
	var revision uint64
	err := sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		row, err := q.GetPartition(ctx, partition)
		if errors.Is(err, sql.ErrNoRows) {
			record.AccountSequence = 100000000000
			return nil
		}
		if err != nil {
			return err
		}
		record, err = (reader{ctx, q}).partition(partition, uint64(row.AccountSequence))
		revision = uint64(row.Revision)
		return err
	})
	return record, revision, err
}

func (r *Repository) CompareAndSwap(ctx context.Context, partition string, expected uint64, record domain.PartitionRecord, commit func(context.Context) error) (bool, error) {
	var swapped bool
	err := sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		row, err := q.GetPartition(ctx, partition)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if uint64(row.Revision) != expected {
			return nil
		}
		// Storage owns one partition aggregate. Replace its relational children
		// in the native transaction; readers never see an intermediate graph.
		if err := q.DeletePartition(ctx, partition); err != nil {
			return err
		}
		if err := q.PutPartitions(ctx, sqlcgen.PutPartitionsParams{Partition: partition, Revision: sqlite.Uint64(expected + 1), AccountSequence: sqlite.Uint64(record.AccountSequence)}); err != nil {
			return err
		}
		if err := (writer{ctx, q}).partition(partition, record); err != nil {
			return err
		}
		if commit != nil {
			if err := commit(ctx); err != nil {
				return err
			}
		}
		swapped = true
		return nil
	})
	return swapped && err == nil, err
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}

type writer struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
