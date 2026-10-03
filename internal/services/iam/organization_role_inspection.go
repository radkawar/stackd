package iam

import (
	"context"
	"errors"

	"stackd/internal/services/organizations"
)

// WithOrganizationServiceRoles keeps the inspected roles and the caller's
// Organizations transition in one native transaction. This uses the repository
// boundary so nested role provisioning can enter its ordinary IAM authority.
func (s *Service) WithOrganizationServiceRoles(ctx context.Context, partition string, accounts []string, fn func(context.Context, map[string]bool) error) error {
	return s.repository.Update(ctx, func(tx WriteTx) error {
		present := make(map[string]bool, len(accounts))
		for _, id := range accounts {
			role, err := tx.Role(Scope{Partition: partition, AccountID: id}, organizations.ServiceLinkedRoleName)
			if err != nil && !errors.Is(err, ErrRecordNotFound) {
				return err
			}
			present[id] = err == nil && role.ServiceLinkedService == organizations.ServicePrincipal
		}
		return fn(tx.Context(), present)
	})
}
