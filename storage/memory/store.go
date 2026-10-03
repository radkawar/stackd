// Package memory implements the transaction mechanics shared by stackd's typed
// in-memory repositories. Resource schemas and record copying belong to their
// service adapters; this package owns locking, cancellation and commit/rollback.
package memory

import (
	"context"
	"errors"
	"maps"
	"sync/atomic"
)

// ErrClosedTransaction reports an expired transaction or a write attempted
// through a read-only transaction.
var ErrClosedTransaction = errors.New("memory transaction is closed or read-only")

// Store owns typed state within a transaction domain. Stores sharing a Domain
// participate in the same transaction when called with its borrowed context.
// A Store must not be copied after construction.
type Store[S any] struct {
	domain *Domain
	state  S
	clone  func(S) S
}

// New takes ownership of initial. clone must return independently mutable state
// without changing its input. Adapters may share immutable nested records when
// they copy those records on both read and write. Neither initial nor callback
// state may be accessed outside the store's callbacks. A nil domain creates an
// independent transaction domain.
func New[S any](domain *Domain, initial S, clone func(S) S) *Store[S] {
	if domain == nil {
		domain = NewDomain()
	}
	return &Store[S]{domain: domain, state: initial, clone: clone}
}

// Transaction limits a repository reader or writer to its callback's lifetime.
// Adapters must call Check before accessing state. Callbacks and their resource
// adapters must not use a transaction concurrently. Related stores must receive
// Context to join the same transaction instead of opening an independent one.
type Transaction struct {
	ctx      context.Context
	writable bool
	closed   atomic.Bool
}

func (t *Transaction) Check(write bool) error {
	if t.closed.Load() || (write && !t.writable) {
		return ErrClosedTransaction
	}
	return t.ctx.Err()
}

// Context carries the transaction to related repositories. It expires with the
// owning domain callback; the resource adapter still closes at its own callback.
func (t *Transaction) Context() context.Context { return t.ctx }

// View observes one consistent snapshot and permits concurrent readers. Its
// state is read-only. Waiting for a lock respects context cancellation.
func (s *Store[S]) View(ctx context.Context, fn func(*S, *Transaction) error) error {
	return s.run(ctx, false, fn)
}

// Update runs fn exactly once after acquiring exclusive access. Callback errors,
// cancellation before commit and panics discard the staged state. Panics are
// propagated after closing the transaction and releasing the lock.
func (s *Store[S]) Update(ctx context.Context, fn func(*S, *Transaction) error) error {
	return s.run(ctx, true, fn)
}

// Attempt gives an API command an explicit savepoint within an existing write.
// A rejected command discards its own related writes without aborting its caller;
// success still waits for the outer transaction's commit. Nested Update failures
// inside the command continue to abort that command even when caught.
// Adapters surviving nested commands must retain the callback's *S root rather
// than a copied struct or map, so accepted child state is visible afterwards.
func (s *Store[S]) Attempt(ctx context.Context, fn func(*S, *Transaction) error) error {
	return s.domain.attempt(ctx, func(ctx context.Context, domain *domainTransaction) error {
		return s.call(ctx, domain, true, fn)
	})
}

func (s *Store[S]) run(ctx context.Context, write bool, fn func(*S, *Transaction) error) error {
	return s.domain.run(ctx, write, func(ctx context.Context, domain *domainTransaction) error {
		return s.call(ctx, domain, write, fn)
	})
}

type storeState[S any] struct {
	store *Store[S]
	value S
}

func (s *storeState[S]) commit()                 { s.store.state = s.value }
func (s *storeState[S]) merge(other stagedState) { s.value = other.(*storeState[S]).value }

func (s *Store[S]) call(ctx context.Context, domain *domainTransaction, write bool, fn func(*S, *Transaction) error) error {
	tx := &Transaction{ctx: ctx, writable: write}
	defer tx.closed.Store(true)
	state, staged := domain.states[s].(*storeState[S])
	if !staged {
		value := s.state
		for parent := domain.parent; parent != nil; parent = parent.parent {
			if previous, exists := parent.states[s].(*storeState[S]); exists {
				value = previous.value
				break
			}
		}
		if write {
			value = s.clone(value)
		}
		state = &storeState[S]{store: s, value: value}
		if write {
			domain.states[s] = state
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(&state.value, tx)
}

// CloneTables copies two levels of typed maps. Values remain shared and must be
// treated as immutable; resource adapters detach records on reads and writes.
func CloneTables[Scope, Key comparable, Record any](tables map[Scope]map[Key]Record) map[Scope]map[Key]Record {
	result := make(map[Scope]map[Key]Record, len(tables))
	for scope, rows := range tables {
		result[scope] = maps.Clone(rows)
	}
	return result
}
