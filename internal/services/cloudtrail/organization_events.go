package cloudtrail

import (
	"context"

	"stackd/journal"
)

// OrganizationEventLog is the existing Organizations journal boundary. Embedding
// preserves unrelated effective-policy events without copying their ownership.
type OrganizationEventLog interface {
	AppendAccountCreationChanged(context.Context, journal.Envelope, journal.AccountCreationChanged) error
	AppendEffectivePolicyChanged(context.Context, journal.Envelope, journal.EffectivePolicyChanged) error
	AppendHandshakeChanged(context.Context, journal.Envelope, journal.HandshakeChanged) error
}

// OrganizationEvents joins terminal asynchronous membership with organization
// trail dependencies. No synthetic CloudTrail API call or second event is emitted.
type OrganizationEvents struct {
	OrganizationEventLog
	Repository    Repository
	Organizations OrganizationView
	Roles         OrganizationRoles
}

func (s OrganizationEvents) AppendAccountCreationChanged(ctx context.Context, envelope journal.Envelope, event journal.AccountCreationChanged) error {
	return s.Repository.Update(ctx, func(tx Transaction) error {
		if err := s.OrganizationEventLog.AppendAccountCreationChanged(tx.Context(), envelope, event); err != nil {
			return err
		}
		if event.State == "SUCCEEDED" {
			return s.reconcile(tx, envelope.Partition, event.AccountID)
		}
		return nil
	})
}

func (s OrganizationEvents) AppendHandshakeChanged(ctx context.Context, envelope journal.Envelope, event journal.HandshakeChanged) error {
	return s.Repository.Update(ctx, func(tx Transaction) error {
		if err := s.OrganizationEventLog.AppendHandshakeChanged(tx.Context(), envelope, event); err != nil {
			return err
		}
		if event.State == "ACCEPTED" && event.TargetAccountID != "" {
			return s.reconcile(tx, envelope.Partition, event.TargetAccountID)
		}
		return nil
	})
}

func (s OrganizationEvents) reconcile(tx Transaction, partition, account string) error {
	org, err := organizationFor(tx.Context(), s.Organizations, partition, account)
	if err != nil {
		return err
	}
	if org.ID == "" || !org.TrustedAccess || !org.AllFeatures {
		return nil
	}
	trails, err := tx.Trails(partition, org.ManagementAccountID)
	if err != nil {
		return err
	}
	for _, trail := range trails {
		if trail.OrganizationID == org.ID {
			return s.Roles.ReconcileOrganizationRoles(tx.Context(), partition, org.ManagementAccountID)
		}
	}
	return nil
}
