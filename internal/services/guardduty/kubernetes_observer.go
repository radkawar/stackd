package guardduty

import (
	"context"
	"errors"

	"stackd/journal"
)

// KubernetesAuditJournal admits immutable source identities in the source's
// transaction. Retries, including inactive-period events, return inserted=false.
type KubernetesAuditJournal interface {
	AppendKubernetesAuditObserved(context.Context, journal.Envelope, journal.KubernetesAuditObserved) (bool, error)
}

// ObserveKubernetesAudit consumes real native audit metadata. Source admission,
// findings and publication intents commit together, without a CloudWatch cursor.
func (s *Service) ObserveKubernetesAudit(ctx context.Context, envelope journal.Envelope, events []journal.KubernetesAuditObserved) error {
	if s.auditJournal == nil {
		return errors.New("GuardDuty Kubernetes audit journal unavailable")
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		detectors, err := tx.AllDetectors()
		if err != nil {
			return err
		}
		now := s.clock.Now()
		for _, event := range events {
			source := envelope
			source.RequestID = event.AuditID
			inserted, err := s.auditJournal.AppendKubernetesAuditObserved(tx.Context(), source, event)
			if err != nil {
				return err
			}
			if !inserted {
				continue
			}
			for _, detector := range detectors {
				if detector.Partition != envelope.Partition || detector.AccountID != envelope.AccountID || detector.Region != envelope.Region {
					continue
				}
				observations, err := detectKubernetesAuditWithLists(tx, detector, event)
				if err != nil {
					return err
				}
				if len(observations) == 0 {
					continue
				}
				filters, err := tx.Filters(detector.Scope, detector.ID)
				if err != nil {
					return err
				}
				for _, observed := range observations {
					id := observationID(detector, observed)
					finding, err := tx.Finding(detector.Scope, detector.ID, id)
					if errors.Is(err, ErrNotFound) || err == nil && findingExpired(finding, now) {
						finding = Finding{Scope: detector.Scope, DetectorID: detector.ID, ID: id, Created: envelope.At}
					} else if err != nil {
						return err
					}
					finding.Observation = observed
					finding.Updated = envelope.At
					finding.Count++
					if err := s.putOccurrence(tx, detector, finding, filters); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
	if err == nil {
		s.jobs.Wake()
	}
	return err
}
