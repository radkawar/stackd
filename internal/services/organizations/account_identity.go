package organizations

import "context"

// AccountIdentity returns registered account metadata to internal consumers.
// It retains removed accounts and keeps partitions separate. An unregistered
// bootstrap identity has the same defaults used by CreateOrganization. Local
// CREATED accounts share one provisioning instant for membership and IAM creation
// metadata. INVITED timestamps must not be used as account creation dates.
func (s *Service) AccountIdentity(ctx context.Context, partition, accountID string) (AccountRecord, error) {
	snapshot, _, err := s.storage.Load(ctx, partition)
	if err != nil {
		return AccountRecord{}, err
	}
	for _, account := range snapshot.Accounts {
		if account.ID == accountID {
			return account, nil
		}
	}
	return bootstrapAccount(accountID), nil
}

func bootstrapAccount(id string) AccountRecord {
	return AccountRecord{ID: id, Name: "Management", Email: id + "@localhost.local", State: "ACTIVE", Status: "ACTIVE"}
}

// PutAccountName updates the account registry and current membership together.
// Account authorizes and validates the name before calling this method inside
// the shared transaction. Creation dates, contacts and emails are independent.
func (s *Service) PutAccountName(ctx context.Context, partition, accountID, name string) error {
	return s.updateAccountIdentity(ctx, partition, accountID, func(account *AccountRecord, _ []AccountRecord) error {
		account.Name = name
		return nil
	})
}

// updateAccountIdentity keeps the registry authoritative for names and emails,
// including when an account has no current organization membership.
func (s *Service) updateAccountIdentity(ctx context.Context, partition, accountID string, change func(*AccountRecord, []AccountRecord) error) error {
	for {
		record, revision, err := s.storage.Load(ctx, partition)
		if err != nil {
			return err
		}
		state := decodeState(record, partition, accountID)
		account, found := state.knownAccounts[accountID]
		if !found {
			account = bootstrapAccount(accountID)
		}
		if err := change(&account, record.Accounts); err != nil {
			return err
		}
		state.knownAccounts[accountID] = account
		if org := state.orgs[state.memberships[accountID]]; org != nil {
			member := org.accounts[accountID]
			member.Name, member.Email = account.Name, account.Email
			org.accounts[accountID] = member
		}
		committed, err := s.storage.CompareAndSwap(ctx, partition, revision, state.record(), nil)
		if err != nil || committed {
			return err
		}
	}
}
