package guardduty

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"stackd/journal"
)

// ObserveAPICall evaluates source-owned API outcomes inside the source event's
// transaction. Its repository must share that transaction domain with the source
// journal. No AWS calls, sample templates or customer effects run here.
func (s *Service) ObserveAPICall(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted, targets []DetectionTarget) error {
	err := s.repository.Update(ctx, func(tx Transaction) error {
		detectors, err := tx.AllDetectors()
		if err != nil {
			return err
		}
		now := s.clock.Now()
		for _, detector := range detectors {
			if detector.Partition != envelope.Partition || detector.AccountID != envelope.AccountID || detector.Region != envelope.Region {
				continue
			}
			observations, err := detectAPICallWithLists(tx, detector, call, targets)
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
				if observed.EventID != "" && finding.Observation.EventID == observed.EventID {
					continue
				}
				finding.Observation = observed
				finding.Updated = envelope.At
				finding.Count++
				if err := s.putOccurrence(tx, detector, finding, filters); err != nil {
					return err
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

// Group by rule, detector, caller, API, origin and affected resource. This is a
// deterministic local aggregation policy, not a claim about AWS's private key.
func observationID(detector Detector, v Observation) string {
	key := strings.Join([]string{detector.ARN, v.Type, v.UserType, v.PrincipalID, v.AccessKeyID, v.ServiceName, v.API, v.SourceIP, v.ResourceType, v.ResourceName}, "\x00")
	if event := v.Kubernetes; event != nil {
		key += "\x00" + strings.Join([]string{event.ClusterID, event.UserName, event.Verb, event.Namespace, event.Resource, event.Subresource, event.Name}, "\x00")
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

// putOccurrence applies the same suppression and publication lifecycle to real
// observations and explicit samples. Manual archival is not automatic suppression.
func (s *Service) putOccurrence(tx Transaction, detector Detector, finding Finding, filters []Filter) error {
	projected, err := findingOutput(finding)
	if err != nil {
		return err
	}
	finding.Suppressed = false
	for _, filter := range filters {
		if filter.Action == "ARCHIVE" && matchesFinding(projected, &filter.Criteria) {
			finding.Suppressed = true
			finding.Archived = true
			break
		}
	}
	now := s.clock.Now().UTC()
	if finding.Suppressed {
		finding.PublishDue = time.Time{}
	} else if finding.LastPublished.IsZero() {
		finding.PublishDue = now
	} else if finding.PublishDue.IsZero() {
		finding.PublishDue = finding.LastPublished.Add(publicationInterval(detector.Frequency))
		if finding.PublishDue.Before(now) {
			finding.PublishDue = now
		}
	}
	if err := tx.PutFinding(finding); err != nil {
		return err
	}
	return s.queueFindingExports(tx, detector, finding)
}
