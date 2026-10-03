package cloudtrail

import (
	"time"

	"github.com/google/uuid"
	"stackd/internal/awscatalog"
)

func ensureDigestStream(tx Transaction, trail TrailRecord, account, region string, now time.Time) (DigestStream, error) {
	streams, err := tx.DigestStreams(trail.ID)
	if err != nil {
		return DigestStream{}, err
	}
	for _, stream := range streams {
		if !stream.Closed && stream.AccountID == account && stream.Region == region && stream.OrganizationID == trail.OrganizationID {
			return stream, nil
		}
	}
	start := now.UTC().Truncate(time.Second)
	for _, previous := range streams {
		if previous.AccountID == account && previous.Region == region && !start.After(previous.Start) {
			start = previous.Start.Add(time.Second)
		}
	}
	stream := DigestStream{
		ID: uuid.NewString(), TrailID: trail.ID, Trail: trail.Key,
		AccountID: account, Region: region, OrganizationID: trail.OrganizationID,
		Bucket: trail.Bucket, Prefix: trail.Prefix, KMSKeyID: trail.KMSKeyID,
		// Native starting digests cover the preceding empty hour and end at
		// logging activation. Delivery latency is scheduled in service time.
		Start: start.Add(-time.Hour), End: start, Due: start, Version: 1,
	}
	return stream, tx.PutDigestStream(stream)
}

func (s *Service) reconcileDigests(tx Transaction, trail TrailRecord) error {
	streams, err := tx.DigestStreams(trail.ID)
	if err != nil {
		return err
	}
	var scopes []Scope
	if trail.Logging && trail.LogFileValidation {
		if s.organizations != nil {
			scopes, err = s.organizations.DigestScopes(tx.Context(), trail)
			if err != nil {
				return err
			}
		} else {
			// Standalone ordinary-trail embeddings have no organization or opt-in
			// authority. Their catalog regions use the normal enabled defaults.
			if trail.OrganizationID != "" {
				return unsupported("No organization view is configured.")
			}
			scopes = []Scope{trail.Key.Scope}
			if trail.MultiRegion && trail.Key.Partition == "aws" {
				for _, region := range awscatalog.CommercialRegions() {
					if region.Name != trail.Key.Region && !region.OptInRequired {
						scopes = append(scopes, Scope{Partition: trail.Key.Partition, AccountID: trail.Key.AccountID, Region: region.Name})
					}
				}
			}
		}
	}
	for _, stream := range streams {
		if stream.Closed {
			continue
		}
		active := false
		for _, scope := range scopes {
			if scope.AccountID == stream.AccountID && scope.Region == stream.Region && trail.OrganizationID == stream.OrganizationID {
				active = true
				break
			}
		}
		if !active {
			stream.Closed, stream.ClosedAt = true, s.clock.Now()
			stream.Version++
			if err := tx.PutDigestStream(stream); err != nil {
				return err
			}
		}
	}
	for _, scope := range scopes {
		if _, err := ensureDigestStream(tx, trail, scope.AccountID, scope.Region, s.clock.Now()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) retainDigestLog(tx Transaction, batch DeliveryRecord, log DigestLog) error {
	trail, err := tx.Trail(batch.Trail)
	if err != nil {
		return err
	}
	if !trail.LogFileValidation {
		return nil
	}
	var stream DigestStream
	if trail.Logging {
		stream, err = ensureDigestStream(tx, trail, batch.AccountID, batch.Region, s.clock.Now())
		if err != nil {
			return err
		}
	} else {
		streams, err := tx.DigestStreams(trail.ID)
		if err != nil {
			return err
		}
		for _, candidate := range streams {
			if candidate.AccountID == batch.AccountID && candidate.Region == batch.Region && candidate.OrganizationID == batch.OrganizationID && s.clock.Now().Before(candidate.End) && (stream.ID == "" || candidate.Start.After(stream.Start)) {
				stream = candidate
			}
		}
		if stream.ID == "" {
			return nil
		}
	}
	// An organization conversion must not reference an old member batch in its new chain.
	if stream.OrganizationID != batch.OrganizationID {
		return nil
	}
	log.StreamID, log.DeliveryID, log.Bucket, log.Object = stream.ID, batch.ID, batch.Bucket, batch.ObjectKey
	log.Delivered = s.clock.Now()
	return tx.PutDigestLog(log)
}
