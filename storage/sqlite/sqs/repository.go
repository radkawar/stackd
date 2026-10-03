// Package sqs stores the SQS domain in service-owned SQLite tables.
package sqs

import (
	"context"
	"database/sql"
	"errors"

	"stackd/storage/sqlite"
	"stackd/storage/sqlite/sqs/internal/sqlcgen"
	domain "stackd/storage/sqs"
)

// Repository uses a database opened by sqlite.Open. The caller owns the database
// lifecycle; closing a stack leaves the repository available for reconstruction.
type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }

func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		return fn(reader{ctx, sqlcgen.New(tx)})
	})
}

func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) (err error) {
		statements := preparedStatements{Tx: tx}
		defer func() {
			if closeErr := statements.close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}()
		return fn(writer{reader{ctx, sqlcgen.New(&statements)}})
	})
}

func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) (err error) {
		statements := preparedStatements{Tx: tx}
		defer func() {
			if closeErr := statements.close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}()
		return fn(writer{reader{ctx, sqlcgen.New(&statements)}})
	})
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}

type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }

// Aggregate writes execute the same SQLC INSERT for every message and receipt.
// Keep native statements for this transaction instead of reparsing each row.
type preparedStatements struct {
	*sql.Tx
	statements map[string]*sql.Stmt
}

func (p *preparedStatements) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	statement := p.statements[query]
	if statement == nil {
		var err error
		statement, err = p.Tx.PrepareContext(ctx, query)
		if err != nil {
			return nil, err
		}
		if p.statements == nil {
			p.statements = make(map[string]*sql.Stmt)
		}
		p.statements[query] = statement
	}
	return statement.ExecContext(ctx, args...)
}

func (p *preparedStatements) close() error {
	var err error
	for _, statement := range p.statements {
		if closeErr := statement.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}
	return err
}
