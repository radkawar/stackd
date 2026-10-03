package organizations

import (
	"context"
	"slices"
)

// publishedPolicy reads the committed service view, not a new calculation from
// attachments. It borrows the caller's transaction without a public API/IAM hop.
func (s *Service) publishedPolicy(ctx context.Context, partition, accountID, kind string) (string, error) {
	record, _, err := s.storage.Load(ctx, partition)
	if err != nil {
		return "", err
	}
	for _, organization := range record.Organizations {
		if !slices.ContainsFunc(organization.Accounts, func(account AccountRecord) bool { return account.ID == accountID }) {
			continue
		}
		if !slices.ContainsFunc(organization.Root.PolicyTypes, func(policy PolicyTypeRecord) bool { return policy.Type == kind && policy.Status == "ENABLED" }) {
			return "", nil
		}
		for _, published := range organization.EffectivePolicies {
			if published.AccountID == accountID && published.PolicyType == kind {
				return published.Content, nil
			}
		}
		return "", nil
	}
	return "", nil
}
