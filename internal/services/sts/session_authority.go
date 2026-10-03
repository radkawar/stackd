package sts

import (
	"context"
	"errors"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// SessionAuthority coordinates signed credential issuance with its current
// identity, role, MFA and policy state. The callback must borrow those resources
// through its context and credential store, and must not perform external
// effects. Its result is publishable only after WithSession returns nil.
// action is AssumeRole, AssumeRoot, GetSessionToken, GetFederationToken or
// GetWebIdentityToken; GetSessionToken
// authenticates credentials and MFA without requiring a permissions decision.
type SessionAuthority interface {
	WithSession(context.Context, string, func(context.Context, CredentialStore, time.Time) error) error
}

// signedSession keeps the service's immutable dependencies and binds credential
// operations and time to the authority callback without copying cache locks.
type signedSession struct {
	*Service
	credentials CredentialStore
	now         func() time.Time
	// Authentication denials can commit attempt limits without publishing a
	// credential. Other operation errors retain the ordinary rollback contract.
	mfaRejection *awswire.Error
}

func withSignedSession[T any](s *Service, ctx context.Context, action string, fn func(*signedSession, context.Context) (*T, *awswire.Error)) (*T, *awswire.Error) {
	if s.sessions == nil {
		return nil, &awswire.Error{Code: "NotImplemented", Message: "Signed session authority is not configured.", StatusCode: 501}
	}
	var output *T
	var rejection *awswire.Error
	err := s.sessions.WithSession(ctx, action, func(ctx context.Context, credentials CredentialStore, instant time.Time) error {
		if credentials == nil {
			return errors.New("session authority supplied no credential store")
		}
		bound := &signedSession{Service: s, credentials: credentials, now: func() time.Time { return instant }}
		var apiErr *awswire.Error
		output, apiErr = fn(bound, ctx)
		if apiErr != nil {
			if apiErr == bound.mfaRejection {
				rejection = apiErr
				return nil
			}
			return apiErr
		}
		return s.appendAPICall(ctx, instant, action, output, nil)
	})
	if err != nil {
		var apiErr *awswire.Error
		if errors.As(err, &apiErr) {
			return nil, apiErr
		}
		return nil, &awswire.Error{Code: "InternalFailure", Message: "The session authority transaction failed.", StatusCode: 500}
	}
	return output, rejection
}

// credentialAuthority supplies the isolated credential-only NewWithIdentity
// provider. Full stacks explicitly supply IAM's wider resource authority.
type credentialAuthority struct{ store *identity.Store }

func (a credentialAuthority) WithSession(ctx context.Context, _ string, fn func(context.Context, CredentialStore, time.Time) error) error {
	return a.store.WithTransaction(ctx, func(ctx context.Context, store *identity.Store, instant time.Time) error {
		return fn(ctx, store, instant)
	})
}
