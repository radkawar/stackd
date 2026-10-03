package iam

import (
	"context"
	"errors"
	"time"

	"stackd/internal/identity"
)

// WithSession gives STS and service execution-role assumptions one transaction for current identity,
// role, policy and MFA reads and credential issuance. The callback receives the
// caller's unchanged metadata and the instant captured after acquiring storage.
// Related repositories join that transaction through its context. The built-in
// memory backend shares this boundary with Organizations controls and features.
// IAM reads must use the supplied context; identity operations must use the
// supplied repository and instant. The callback's context and repository must
// not be retained, used concurrently, or used to re-enter this authority.
// External effects belong outside the callback.
// Callback errors, cancellation and storage failures roll back this command's
// writes. An enclosing transaction remains available to record its rejection.
func (s *Service) WithSession(ctx context.Context, fn func(context.Context, identity.Repository, time.Time) error) error {
	if fn == nil {
		return errors.New("session callback is required")
	}
	return s.withAuthorityTransaction(ctx, func(ctx context.Context, _ WriteTx, repository identity.Repository, now time.Time) error {
		return fn(ctx, repository, now)
	})
}

func (s *Service) withAuthorityTransaction(ctx context.Context, fn func(context.Context, WriteTx, identity.Repository, time.Time) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if transaction, ok := ctx.Value(transactionKey{}).(serviceTransaction); ok && transaction.service == s {
		return errors.New("session authority cannot re-enter an IAM transaction")
	}
	return s.repository.Attempt(ctx, func(tx WriteTx) error {
		now := s.clock.Now().UTC()
		callbackCtx, cancel := context.WithCancel(context.WithValue(tx.Context(), transactionKey{}, serviceTransaction{service: s, tx: tx, currentTime: now}))
		defer cancel()
		repository := &CredentialRepository{read: tx, write: tx, request: callbackCtx, events: s.credentialEvents}
		if err := fn(callbackCtx, tx, repository, now); err != nil {
			return err
		}
		return callbackCtx.Err()
	})
}
