package stackd

import (
	"context"
	"fmt"
	"time"

	"stackd/internal/identity"
	"stackd/internal/services/iam"
	"stackd/internal/services/organizations"
	"stackd/internal/services/sts"
)

type iamSessions struct {
	service      *iam.Service
	credentials  *identity.Store
	organization *organizations.Service
}

func (s iamSessions) WithSession(ctx context.Context, action string, fn func(context.Context, sts.CredentialStore, time.Time) error) error {
	if action != "AssumeRole" && action != "GetSessionToken" && action != "GetFederationToken" && action != "AssumeRoot" && action != "GetWebIdentityToken" {
		return fmt.Errorf("invalid signed session action %q", action)
	}
	return s.service.WithSession(ctx, func(ctx context.Context, repository identity.Repository, instant time.Time) error {
		credentials := s.credentials.WithRepositoryAt(repository, instant)
		if action == "GetSessionToken" {
			// Authentication is independent of identity policies and SCPs.
			return fn(ctx, credentials, instant)
		}
		// Reuse one decoded control hierarchy for the action/tag/source checks.
		// The repository context keeps Organizations in IAM's transaction;
		// the memory domain owns atomicity through credential publication.
		return s.organization.WithPolicySnapshot(ctx, func(ctx context.Context) error {
			return fn(ctx, credentials, instant)
		})
	})
}
