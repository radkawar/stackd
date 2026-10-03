package eventbridge

import (
	"context"
	"errors"
	"time"

	"stackd/internal/scheduler"
)

func (s *Service) deliverArchive(ctx context.Context, delivery DeliveryRecord, event EventRecord, started time.Time) error {
	var archive ArchiveRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		archive, err = r.ArchiveByID(delivery.ArchiveID)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return s.finishDelivery(ctx, delivery, event, failure("ResourceNotFoundException", "Archive resource not found."), false, started)
	}
	if err != nil {
		return err
	}
	// Native archives retain only the customer-visible envelope. X-Ray trace
	// metadata is deliberately excluded, so replay starts without the trace.
	body, err := eventBody(event)
	if err != nil {
		return err
	}
	payload, rejected := s.encryptArchivePayload(ctx, archive, []byte(body), archiveRuleKey(archive).ARN())
	if rejected != nil {
		retry := false
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			retained, err := tx.ArchiveByID(archive.ID)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil || retained.Version == archive.Version {
				return err
			}
			current, err := tx.Delivery(delivery.ID)
			if err != nil || current.Version != delivery.Version {
				return err
			}
			current.Version++
			current.Due = s.clock.Now()
			retry = true
			return tx.PutDelivery(current)
		}); err != nil {
			return err
		}
		if retry {
			return nil
		}
		return s.finishDelivery(ctx, delivery, event, rejected, false, started)
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Delivery(delivery.ID)
		if err != nil || current.Version != delivery.Version {
			return err
		}
		retained, err := tx.ArchiveByID(archive.ID)
		if errors.Is(err, ErrNotFound) {
			current.State, current.LastErrorCode, current.LastErrorMessage = "failed", "NO_RESOURCE", "Archive resource not found."
			current.Version++
			if err := s.stageDeliveryMetrics(tx, delivery, current, event, started, true); err != nil {
				return err
			}
			return tx.PutDelivery(current)
		}
		if err != nil {
			return err
		}
		if retained.Version != archive.Version {
			// Configuration changed while KMS ran; retry against its current key
			// and retention rather than committing an obsolete configuration.
			current.Version++
			current.Due = s.clock.Now()
			return tx.PutDelivery(current)
		}
		_, err = tx.ArchiveEntry(archive.ID, event.ID)
		if errors.Is(err, ErrNotFound) {
			entry := ArchiveEntry{ArchiveID: archive.ID, ID: event.ID, Time: event.Time,
				Ingested: event.Accepted, Payload: payload, SizeBytes: int64(len(body)), KeyVersion: archive.KeyVersion}
			// TODO: Comeback match AWS archive physical SizeBytes accounting; local counts use retained event-envelope bytes, not AWS's private encoding.
			if retained.RetentionDays != 0 {
				entry.Expires = time.Unix(event.Accepted.Unix()+int64(retained.RetentionDays)*86400, int64(event.Accepted.Nanosecond())).UTC()
			}
			if entry.Expires.IsZero() || entry.Expires.After(s.clock.Now()) {
				if err := tx.PutArchiveEntry(entry); err != nil {
					return err
				}
				retained.EventCount++
				retained.SizeBytes += entry.SizeBytes
				if err := tx.PutArchive(retained); err != nil {
					return err
				}
			}
		} else if err != nil {
			return err
		}
		current.Version++
		current.Attempts++
		current.State = "delivered"
		if err := s.stageDeliveryMetrics(tx, delivery, current, event, started, true); err != nil {
			return err
		}
		return tx.PutDelivery(current)
	})
}

// archiveExpirationJobs removes retained payload and adjusts its counters in the
// same transaction. Ingestion time, not the customer event timestamp, owns TTL.
type archiveExpirationJobs struct{ s *Service }

func (j archiveExpirationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var entry ArchiveEntry
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		entry, found, err = r.NextArchiveExpiration()
		return err
	})
	return scheduler.Job{Key: entry.ArchiveID + "/" + entry.ID, Due: entry.Expires}, found, err
}

func (j archiveExpirationJobs) Run(ctx context.Context, job scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		entry, found, err := tx.NextArchiveExpiration()
		if err != nil || !found {
			return err
		}
		if entry.ArchiveID+"/"+entry.ID != job.Key || !entry.Expires.Equal(job.Due) || entry.Expires.After(j.s.clock.Now()) {
			return nil
		}
		archive, err := tx.ArchiveByID(entry.ArchiveID)
		if err != nil {
			return err
		}
		if err := tx.DeleteArchiveEntry(entry.ArchiveID, entry.ID); err != nil {
			return err
		}
		archive.EventCount--
		archive.SizeBytes -= entry.SizeBytes
		return tx.PutArchive(archive)
	})
}
