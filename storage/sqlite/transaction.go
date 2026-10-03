package sqlite

import (
	"context"
	"database/sql"
	"errors"
)

type transactionKey struct{ db *sql.DB }
type transactionScope struct {
	tx       *sql.Tx
	readOnly bool
	failure  error
}

var errAborted = errors.New("SQLite transaction aborted")

// TransactOwned requires a new transaction, so success means the native commit
// has finished. Use it before publishing process-local state, such as a clock
// advance, which cannot roll back with an enclosing repository callback.
func TransactOwned(ctx context.Context, db *sql.DB, readOnly bool, fn func(context.Context, *sql.Tx) error) error {
	if _, ok := ctx.Value(transactionKey{db}).(*transactionScope); ok {
		return errors.New("operation requires its own SQLite transaction")
	}
	return Transact(ctx, db, readOnly, fn)
}

// Transact calls fn once, borrowing the transaction carried by ctx for this DB
// when present. Related typed repositories commit together. A failed nested
// write aborts the owner even if the caller catches its error or panic.
// Callbacks must use the supplied context for queries and related repositories;
// it expires on callback return and must not be used concurrently.
// Read-only callbacks must expose only their service's Reader and use the SQL
// handle only for queries.
// An owned transaction joins cancellation-triggered rollback before returning.
func Transact(ctx context.Context, db *sql.DB, readOnly bool, fn func(context.Context, *sql.Tx) error) error {
	if current, ok := ctx.Value(transactionKey{db}).(*transactionScope); ok {
		return current.call(ctx, readOnly, fn)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	// Tx.Rollback can return ErrTxDone while database/sql's cancellation
	// goroutine is still rolling back. Closing the leased connection joins
	// that work before a service can close its repository and remove its files.
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: readOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current := &transactionScope{tx: tx, readOnly: readOnly}
	if err := current.call(context.WithValue(ctx, transactionKey{db}, current), readOnly, fn); err != nil {
		return err
	}
	return tx.Commit()
}

// Attempt gives an API command an explicit native SAVEPOINT in an enclosing
// write. A failed command rolls back its related writes without poisoning the
// caller; ordinary Transact nesting retains its abort-on-error contract.
func Attempt(ctx context.Context, db *sql.DB, fn func(context.Context, *sql.Tx) error) (err error) {
	parent, nested := ctx.Value(transactionKey{db}).(*transactionScope)
	if !nested {
		return Transact(ctx, db, false, fn)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if parent.failure != nil {
		return parent.failure
	}
	if parent.readOnly {
		return errors.New("cannot write through a read-only SQLite transaction")
	}
	if _, err := parent.tx.ExecContext(ctx, "SAVEPOINT stackd_command"); err != nil {
		parent.failure = err
		return err
	}
	child := &transactionScope{tx: parent.tx}
	borrowed, cancel := context.WithCancel(context.WithValue(ctx, transactionKey{db}, child))
	defer cancel()
	completed := false
	defer func() {
		// A canceled callback must not leave its savepoint open. Failure to
		// restore/release the native boundary aborts the enclosing transaction.
		cleanup := context.WithoutCancel(ctx)
		if !completed || err != nil {
			if _, failure := parent.tx.ExecContext(cleanup, "ROLLBACK TO SAVEPOINT stackd_command"); failure != nil {
				parent.failure, err = failure, failure
			}
		}
		if _, failure := parent.tx.ExecContext(cleanup, "RELEASE SAVEPOINT stackd_command"); failure != nil {
			parent.failure, err = failure, failure
		}
	}()
	err = child.call(borrowed, false, fn)
	completed = true
	return err
}

func (t *transactionScope) call(ctx context.Context, readOnly bool, fn func(context.Context, *sql.Tx) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if t.failure != nil {
		return t.failure
	}
	if t.readOnly && !readOnly {
		return errors.New("cannot write through a read-only SQLite transaction")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	completed := false
	defer func() {
		if !readOnly {
			if !completed {
				t.failure = errAborted
			} else if err != nil {
				t.failure = err
			}
		}
	}()
	err = fn(ctx, t.tx)
	completed = true
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = t.failure
	}
	return err
}
