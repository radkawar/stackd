package organizations

import (
	"context"

	"stackd/journal"
)

// Events joins the transaction supplied by Organizations. Append
// failure aborts the Organizations transition, including any joined IAM resources
// and contacts. Implementations must not deliver external effects here.
type Events interface {
	AppendAccountCreationChanged(context.Context, journal.Envelope, journal.AccountCreationChanged) error
	AppendEffectivePolicyChanged(context.Context, journal.Envelope, journal.EffectivePolicyChanged) error
	AppendHandshakeChanged(context.Context, journal.Envelope, journal.HandshakeChanged) error
}

func (s *operationState) recordAccountCreation(o *orgState, job AccountCreationRecord) {
	instant := job.RequestedAt
	if job.State != "IN_PROGRESS" {
		instant = job.CompletedAt
	}
	change := journal.AccountCreationChanged{OrganizationID: o.organization.ID, CreationRequestID: job.ID, State: job.State, FailureReason: job.FailureReason}
	if job.State == "SUCCEEDED" {
		change.AccountID = job.AccountID
	}
	s.events = append(s.events, journal.Event{
		Envelope:               journal.Envelope{At: instant, Partition: s.partition, AccountID: o.organization.MasterAccountID, Region: job.RequestRegion, RequestID: job.RequestID, ActorARN: job.ActorARN},
		AccountCreationChanged: change,
	})
}
