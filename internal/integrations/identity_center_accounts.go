package integrations

import (
	"context"
	"errors"

	"stackd/internal/services/identitycenter"
	"stackd/storage/organizations"
)

// IdentityCenterAccounts reads current Organizations membership in the borrowed
// transaction. It does not invent organization trust from account-ID syntax.
type IdentityCenterAccounts struct{ Storage organizations.Storage }

var _ identitycenter.Accounts = IdentityCenterAccounts{}

func (a IdentityCenterAccounts) Allowed(ctx context.Context, scope identitycenter.Scope, targetID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if scope.Partition == "" || scope.AccountID == "" || targetID == "" {
		return false, nil
	}
	if scope.AccountID == targetID {
		return true, nil
	}
	if a.Storage == nil {
		return false, errors.New("Identity Center Organizations authority is not configured")
	}
	state, _, err := a.Storage.Load(ctx, scope.Partition)
	if err != nil {
		return false, err
	}
	for _, org := range state.Organizations {
		ownerActive, targetActive := false, false
		for _, account := range org.Accounts {
			if account.State != "ACTIVE" {
				continue
			}
			if account.ID == scope.AccountID {
				ownerActive = true
			}
			if account.ID == targetID {
				targetActive = true
			}
		}
		if !ownerActive || !targetActive {
			continue
		}
		trusted := false
		for _, service := range org.Services {
			if service.Principal == "sso.amazonaws.com" {
				trusted = true
				break
			}
		}
		if !trusted {
			return false, nil
		}
		if org.Organization.MasterAccountID == scope.AccountID {
			return true, nil
		}
		// Delegation never grants control over the management account.
		// https://docs.aws.amazon.com/singlesignon/latest/userguide/delegated-admin.html
		if targetID == org.Organization.MasterAccountID {
			return false, nil
		}
		for _, delegation := range org.Delegations {
			if delegation.AccountID == scope.AccountID && delegation.Principal == "sso.amazonaws.com" {
				return true, nil
			}
		}
		return false, nil
	}
	return false, nil
}
