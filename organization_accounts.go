package stackd

import (
	"context"

	"stackd/internal/services/account"
	"stackd/internal/services/iam"
	"stackd/internal/services/organizations"
)

// organizationAccounts composes service-owned initialization in IAM's authority
// transaction. A failed contact write or organization commit publishes no roles,
// contacts or membership; retries copy current management contact information.
type organizationAccounts struct {
	identity *iam.Service
	accounts *account.Service
}

func (p organizationAccounts) WithAccountProvisioning(ctx context.Context, in organizations.AccountProvisioning, commit func(context.Context) error) error {
	return p.identity.WithAccountRoles(ctx, in, func(ctx context.Context) error {
		if in.AccessRoleName != "" {
			if err := p.accounts.InitializeMemberContact(ctx, in.Partition, in.ManagementAccountID, in.AccountID, in.AccountName); err != nil {
				return err
			}
		}
		return commit(ctx)
	})
}
