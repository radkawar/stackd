package organizations

import (
	"context"
	"errors"
	"strings"
)

// ErrPrimaryEmailInUse means another account owns the requested root email.
var ErrPrimaryEmailInUse = errors.New("the primary email address is already in use")

// CheckPrimaryEmail checks the partition-wide registry. Pending requests do not
// own an address; publication checks it again in the completion transaction.
func (s *Service) CheckPrimaryEmail(ctx context.Context, partition, email string) error {
	record, _, err := s.storage.Load(ctx, partition)
	if err != nil {
		return err
	}
	return primaryEmailAvailable(record.Accounts, "", email)
}

func primaryEmailAvailable(accounts []AccountRecord, except, email string) error {
	for _, account := range accounts {
		if account.ID != except && strings.EqualFold(account.Email, email) {
			return ErrPrimaryEmailInUse
		}
	}
	return nil
}

// PutPrimaryEmail publishes verified email ownership in the registry and current
// membership atomically. Account calls this from its completion transaction.
// IAM passwords, MFA and credentials remain owned by IAM and are not replaced.
func (s *Service) PutPrimaryEmail(ctx context.Context, partition, accountID, email string) error {
	return s.updateAccountIdentity(ctx, partition, accountID, func(account *AccountRecord, accounts []AccountRecord) error {
		if err := primaryEmailAvailable(accounts, accountID, email); err != nil {
			return err
		}
		account.Email = email
		return nil
	})
}
