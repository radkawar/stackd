package iam

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

// RecordActivity records an attempt by a verified request or accepted job,
// including denied attempts. Its context carries the trusted caller snapshot;
// recording does not authenticate that principal again.
// Credential usage and principal activity commit together before the target
// service runs. This is a separate transaction from the target service's effects.
func (s *Service) RecordActivity(ctx context.Context, serviceNamespace, operationName string) error {
	m := awsctx.FromContext(ctx)
	if m.AccessKeyID == "" || m.Partition == "" || m.AccountID == "" || m.Region == "" || serviceNamespace == "" || operationName == "" {
		return identity.ErrInvalidPrincipal
	}
	return s.repository.Update(ctx, func(tx WriteTx) error {
		instant := s.clock.Now().UTC()
		store := s.credentials.WithRepositoryAt(&CredentialRepository{read: tx, write: tx, request: ctx}, instant)
		principalARN, principalID := m.PrincipalARN, m.PrincipalID
		if m.SessionType == string(identity.SessionTypeAssumeRole) || m.SessionType == string(identity.SessionTypeFederation) {
			principalARN, principalID = m.IssuerARN, m.IssuerID
		}
		if principalARN == "" || principalID == "" {
			return identity.ErrInvalidPrincipal
		}
		if err := store.RecordUsage(ctx, m.AccessKeyID, serviceNamespace, m.Region); err != nil {
			return err
		}
		// RecordUsage intentionally coalesces access-key observations. Activity
		// is independent: another action at the same instant still needs a row.
		return tx.PutPrincipalActivity(Scope{Partition: m.Partition, AccountID: m.AccountID}, PrincipalActivity{
			PrincipalID: principalID, PrincipalARN: principalARN,
			ServiceNamespace: serviceNamespace, ActionName: operationName,
			Region: m.Region, LastAuthenticated: instant,
		})
	})
}
