package organizations

import "context"

const (
	ServicePrincipal      = "organizations.amazonaws.com"
	ServiceLinkedRoleName = "AWSServiceRoleForOrganizations"
)

// ServiceRoleDependency returns the organization requiring this account's
// service-linked role, or an empty ARN when deletion is allowed. All-features
// membership requires the role; consolidated billing does not. Callers making
// a deletion decision must hold a transaction that both stores join through ctx.
func (s *Service) ServiceRoleDependency(ctx context.Context, partition, accountID string) (string, error) {
	record, _, err := s.storage.Load(ctx, partition)
	if err != nil {
		return "", err
	}
	for _, organization := range record.Organizations {
		if organization.Organization.FeatureSet != "ALL" {
			continue
		}
		for _, account := range organization.Accounts {
			if account.ID == accountID {
				return organization.Organization.ARN, nil
			}
		}
	}
	return "", nil
}
