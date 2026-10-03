package eventbridge

import (
	"context"
	"errors"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

// Migration belongs to the archive incarnation. Each job handles one retained
// envelope; it never holds the resource transaction across KMS. Entries label
// their encryption generation so late ingestion and out-of-order event times
// cannot escape a cursor-based migration or overwrite migrated ciphertext.
type archiveMigrationJobs struct{ s *Service }

func (j archiveMigrationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var archive ArchiveRecord
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		archive, found, err = r.NextArchiveMigration()
		return err
	})
	return scheduler.Job{Key: archive.ID, Version: archive.Version, Due: archive.MigrationDue}, found, err
}

func (j archiveMigrationJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	var archive ArchiveRecord
	var entry ArchiveEntry
	var selected, found bool
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		archive, err = r.ArchiveByID(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		selected = archive.Version == job.Version && !archive.MigrationDue.IsZero() && !archive.MigrationDue.After(s.clock.Now())
		if !selected {
			return nil
		}
		entry, found, err = r.NextArchiveMigrationEntry(archive.ID, archive.KeyVersion)
		return err
	})
	if err != nil || !selected {
		return err
	}
	payload := entry.Payload
	var rejected *awswire.Error
	if found {
		// Keep the wire error outside the repository transaction just like
		// ingestion and replay. A denied rewrap never destroys the old payload.
		migrated, wire := s.migrateArchivePayload(ctx, archive, entry)
		if wire == nil {
			payload = migrated
		}
		rejected = wire
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.ArchiveByID(archive.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil || current.Version != archive.Version {
			return err
		}
		current.Version++
		current.MigrationDue = s.clock.Now()
		switch {
		case rejected != nil:
			current.MigrationDue = time.Time{}
			current.KeyARN, current.KmsKeyIdentifier = current.PreviousKeyARN, current.PreviousKmsKeyIdentifier
			current.PreviousKeyARN, current.PreviousKmsKeyIdentifier = "", ""
			current.State, current.StateReason = "UPDATE_FAILED", archiveMigrationFailure(rejected)
		case !found:
			current.MigrationDue = time.Time{}
			current.PreviousKeyARN, current.PreviousKmsKeyIdentifier = "", ""
			if current.KeyARN == "" {
				current.KmsKeyIdentifier = ""
			}
			if current.State == "UPDATING" {
				current.State, current.StateReason = "ENABLED", ""
			}
		default:
			retained, err := tx.ArchiveEntry(archive.ID, entry.ID)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if err == nil && retained.KeyVersion == entry.KeyVersion {
				retained.Payload, retained.KeyVersion = payload, archive.KeyVersion
				retained.RuleContext = false
				if err := tx.PutArchiveEntry(retained); err != nil {
					return err
				}
			}
		}
		return tx.PutArchive(current)
	})
}

func archiveMigrationFailure(rejected *awswire.Error) string {
	if rejected.Code == "AccessDeniedException" || rejected.Code == "NotFoundException" {
		return "events.amazonaws.com is not authorized to access the key because the resource does not exist in this Region, no resource-based policies allow access, or a resource-based policy explicitly denies access. Please ensure that events.amazonaws.com has permissions to access required KMS APIs."
	}
	return rejected.Message
}
