package identity

import (
	"context"
	"errors"
	"time"
)

// WithTransaction runs credential operations against one authoritative snapshot
// and instant. The borrowed store and context are valid only in the callback;
// they must not be retained or used concurrently. IAM-backed consumers use
// IAM's wider session authority to include resource and policy reads as well.
func (s *Store) WithTransaction(ctx context.Context, fn func(context.Context, *Store, time.Time) error) error {
	if fn == nil {
		return errors.New("identity transaction callback is required")
	}
	if owner, ok := ctx.Value(transactionOwnerKey{}).(*Store); ok && owner == s {
		return errors.New("identity transaction cannot be re-entered")
	}
	if _, borrowed := s.repository.(*transactionRepository); borrowed {
		return errors.New("identity transaction cannot be re-entered")
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		instant := s.now().UTC()
		borrowedCtx, cancel := context.WithCancel(context.WithValue(ctx, transactionOwnerKey{}, s))
		defer cancel()
		repository := &transactionRepository{tx: tx, ctx: borrowedCtx}
		if err := fn(borrowedCtx, s.WithRepositoryAt(repository, instant), instant); err != nil {
			return err
		}
		return borrowedCtx.Err()
	})
}

type transactionOwnerKey struct{}

type transactionRepository struct {
	tx  Transaction
	ctx context.Context
}

func (r *transactionRepository) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.ctx.Err()
}

func (r *transactionRepository) View(ctx context.Context, fn func(Reader) error) error {
	if err := r.check(ctx); err != nil {
		return err
	}
	if err := fn(r.tx); err != nil {
		return err
	}
	return r.check(ctx)
}

func (r *transactionRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	if err := r.check(ctx); err != nil {
		return err
	}
	if err := fn(r.tx); err != nil {
		return err
	}
	return r.check(ctx)
}
