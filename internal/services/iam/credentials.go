package iam

import (
	"context"
	"stackd/internal/identity"
	"time"
)

// CredentialStore is the IAM credential lifecycle consumed by this service.
// Authentication and session issuance remain separate consumers of the backing
// identity repository; IAM does not depend on a concrete storage implementation.
type CredentialStore interface {
	WithRepository(identity.Repository) *identity.Store
	WithRepositoryAt(identity.Repository, time.Time) *identity.Store
	CreateAccessKey(identity.Principal) (identity.Credential, error)
	ListAccessKeys(accountID, principalID string) ([]identity.AccessKey, error)
	UpdateAccessKey(accountID, principalID, accessKeyID string, status identity.Status) error
	DeleteAccessKey(accountID, principalID, accessKeyID string) error
	AccessKeyLastUsed(accountID, accessKeyID string) (identity.AccessKey, identity.LastUsed, error)
	RenamePrincipal(identity.Principal) error
	DeletePrincipal(accountID, principalID string) error
}

func (s *Service) credentialStore(ctx context.Context) CredentialStore {
	if transaction, ok := ctx.Value(transactionKey{}).(serviceTransaction); ok && transaction.service == s {
		repository := &CredentialRepository{read: transaction.tx, request: ctx}
		if tx, ok := transaction.tx.(WriteTx); ok {
			repository.write = tx
		}
		return s.credentials.WithRepositoryAt(repository, transaction.currentTime)
	}
	return s.credentials
}
