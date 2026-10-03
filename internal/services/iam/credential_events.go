package iam

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// SessionEvents appends a typed credential-publication event in the transaction
// carried by ctx. Implementations must not publish outside that transaction or
// perform external effects. An append error aborts credential issuance.
type SessionEvents interface {
	AppendSessionIssued(context.Context, journal.Envelope, journal.SessionIssued) error
}

// CredentialEvents also records successful access-key API mutations in IAM's
// transaction. It has the same transaction and external-effect rules as SessionEvents.
type CredentialEvents interface {
	SessionEvents
	AppendAccessKeyChanged(context.Context, journal.Envelope, journal.AccessKeyChanged) error
}

func (s *Service) appendAccessKeyChange(ctx context.Context, a *account, m awsctx.Metadata, change journal.AccessKeyChanged) *awswire.Error {
	if s.credentialEvents == nil {
		return nil
	}
	envelope := journal.Envelope{At: a.currentTime, Partition: m.Partition, AccountID: m.AccountID, Region: m.Region, RequestID: m.RequestID, ActorARN: m.PrincipalARN}
	if err := s.credentialEvents.AppendAccessKeyChanged(ctx, envelope, change); err != nil {
		return &awswire.Error{Code: "ServiceFailure", Message: "Unable to append credential event.", StatusCode: 500}
	}
	return nil
}
