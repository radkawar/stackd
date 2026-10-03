package integrations

import (
	"context"
	"errors"
	"sync"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

type serviceSessionKey struct{ roleARN, sessionName, service, sourceARN, externalID, issuerARN string }

// serviceRoleSessions reuses issued sessions without retaining authority across
// expiration, revocation, or rollback of the transaction that issued them.
// Never hold its mutex while entering IAM: a caller may own the shared transaction.
// Current resource authorization remains the destination service's responsibility.
type serviceRoleSessions struct {
	mu          sync.Mutex
	credentials map[serviceSessionKey]identity.Credential
}

func (s *serviceRoleSessions) context(ctx context.Context, authority ServiceRoles, source awsctx.ServicePrincipal, roleARN, sessionName, externalID string) (context.Context, error) {
	key := serviceSessionKey{roleARN: roleARN, sessionName: sessionName, service: source.Name, sourceARN: source.SourceARN, externalID: externalID}
	return s.contextFor(ctx, authority, key, func(ctx context.Context) (identity.Credential, error) {
		credential, rejected := authority.assume(ctx, source, roleARN, identity.RoleSessionSpec{SessionName: sessionName}, externalID)
		if rejected != nil {
			return identity.Credential{}, rejected
		}
		return credential, nil
	})
}

// contextFor also serves ordinary STS role chains. issuerARN separates a chained
// session from a direct service assumption of the same target role.
func (s *serviceRoleSessions) contextFor(ctx context.Context, authority ServiceRoles, key serviceSessionKey, issue func(context.Context) (identity.Credential, error)) (context.Context, error) {
	s.mu.Lock()
	credential := s.credentials[key]
	s.mu.Unlock()
	valid := false
	if credential.AccessKeyID != "" && authority.IAM != nil {
		err := authority.IAM.WithSession(ctx, func(ctx context.Context, repository identity.Repository, now time.Time) error {
			if !now.Add(time.Minute).Before(credential.Expiration) {
				return nil
			}
			return repository.View(ctx, func(reader identity.Reader) error {
				record, err := reader.Get(credential.AccessKeyID)
				if errors.Is(err, identity.ErrNotFound) {
					return nil
				}
				if err != nil {
					return err
				}
				valid = record.Status == identity.Active && record.Credential.IssuerARN == key.roleARN
				return nil
			})
		})
		if err != nil {
			return nil, err
		}
	}
	if !valid {
		issued, err := issue(ctx)
		if err != nil {
			return nil, err
		}
		credential = issued
		s.mu.Lock()
		if s.credentials == nil {
			s.credentials = make(map[serviceSessionKey]identity.Credential)
		}
		s.credentials[key] = credential
		s.mu.Unlock()
	}
	service, rejected := serviceRoleRequestContext(ctx, credential, awsctx.FromContext(ctx).Region, key.service)
	if rejected != nil {
		return nil, rejected
	}
	return service, nil
}
