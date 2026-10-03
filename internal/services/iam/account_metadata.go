package iam

import (
	"context"
	"errors"
	"net/http"
	"time"

	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/organizations"
)

// AccountIdentitySource supplies the current account name and email for IAM's
// default password restrictions. Storage failures must be returned.
type AccountIdentitySource interface {
	AccountIdentity(context.Context, string, string) (organizations.AccountRecord, error)
}

// AccountExists recognizes the authenticated bootstrap account and accounts
// already represented in IAM state. It does not provision an account merely
// because a policy mentions its ID.
func (s *Service) AccountExists(ctx context.Context, partition, accountID string) (bool, error) {
	m := awsctx.FromContext(ctx)
	if partition == m.Partition && accountID == m.AccountID {
		return true, ctx.Err()
	}
	found := false
	err := s.view(ctx, func(tx ReadTx) error {
		scopes, err := tx.Scopes(partition)
		if err != nil {
			return err
		}
		for _, scope := range scopes {
			if scope.AccountID == accountID {
				found = true
				break
			}
		}
		return nil
	})
	return found, err
}

// SetAccountIdentitySource connects the account registry before serving.
func (s *Service) SetAccountIdentitySource(source AccountIdentitySource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accountIdentity = source
}

// prepareAccountIdentity initializes local metadata and checks the current account
// identity when applying default password restrictions. Run within the transaction:
// the first root response needs the date, but a failed operation must not save it.
func (s *Service) prepareAccountIdentity(ctx context.Context, a *account, m awsctx.Metadata) *awswire.Error {
	decoded, _ := awsapi.FromContext(ctx)
	password := ""
	switch in := decoded.Input.(type) {
	case *iamapi.CreateLoginProfileInput:
		password = inputString(in.Password)
	case *iamapi.UpdateLoginProfileInput:
		password = inputString(in.Password)
	case *iamapi.ChangePasswordInput:
		password = inputString(in.NewPassword)
	}
	if password != "" && a.settings.PasswordPolicy == nil {
		s.mu.Lock()
		source := s.accountIdentity
		s.mu.Unlock()
		if source != nil {
			record, err := source.AccountIdentity(ctx, m.Partition, m.AccountID)
			if err != nil {
				return &awswire.Error{Code: "ServiceFailure", Message: "Unable to read account identity.", StatusCode: http.StatusInternalServerError}
			}
			if password == record.Name || password == record.Email {
				return passwordViolation()
			}
		}
	}
	if a.metadata == nil {
		a.metadata = &AccountMetadata{CreatedAt: a.currentTime}
	}
	return nil
}

// AccountCreationTime returns the same stable creation date used by IAM root
// responses and credential reports. First use initializes metadata inside the
// caller's shared transaction; a failed outer operation leaves no date behind.
func (s *Service) AccountCreationTime(ctx context.Context, partition, accountID string) (time.Time, error) {
	var created time.Time
	err := s.repository.Update(ctx, func(tx WriteTx) error {
		scope := Scope{Partition: partition, AccountID: accountID}
		metadata, err := tx.AccountMetadata(scope)
		if errors.Is(err, ErrRecordNotFound) {
			metadata = AccountMetadata{CreatedAt: s.clock.Now().UTC()}
			if err := tx.PutAccountMetadata(scope, metadata); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		created = metadata.CreatedAt
		return nil
	})
	return created, err
}
