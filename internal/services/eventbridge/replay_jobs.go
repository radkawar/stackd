package eventbridge

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type replayJobs struct{ s *Service }

func (j replayJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var replay ReplayRecord
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		replay, found, err = r.NextReplay()
		return err
	})
	return scheduler.Job{Key: replay.Key.ARN(), Version: replay.Version, Due: replay.Due}, found, err
}

func (j replayJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	var replay ReplayRecord
	var archive ArchiveRecord
	var entry ArchiveEntry
	var selected, found, missing bool
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		replay, selected, err = r.NextReplay()
		if err != nil || !selected {
			return err
		}
		selected = replay.Key.ARN() == job.Key && replay.Version == job.Version && !replay.Due.After(s.clock.Now())
		if !selected || replay.State == "CANCELLING" {
			return nil
		}
		archive, err = r.ArchiveByID(replay.ArchiveID)
		if errors.Is(err, ErrNotFound) {
			missing = true
			return nil
		}
		if err != nil || replay.State == "STARTING" {
			return err
		}
		start := replay.StartTime.Truncate(time.Minute)
		end := replay.EndTime.Truncate(time.Minute).Add(time.Minute)
		entry, found, err = r.NextArchiveEntry(replay.ArchiveID, start, end, replay.Cursor)
		return err
	})
	if err != nil || !selected {
		return err
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: replay.Key.Partition, AccountID: replay.Key.Account, Region: replay.Key.Region,
		RequestID: replay.RequestID, ParentEventID: entry.ID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "events.amazonaws.com", SourceARN: replay.Key.ARN(), Type: "AWSService"},
	})
	state, reason := replay.State, ""
	var event *EventRecord
	switch {
	case replay.State == "CANCELLING":
		state = "CANCELLED"
	case missing:
		state, reason = "FAILED", "Archive resource not found."
	case replay.State == "STARTING":
		state = "RUNNING"
	case !found:
		state = "COMPLETED"
	default:
		// The native cursor scans whole minute buckets even if the exact
		// replay window excludes every event in the bucket.
		replay.Cursor = ArchiveCursor{Time: entry.Time, ID: entry.ID}
		if !entry.Time.Before(replay.StartTime) && entry.Time.Before(replay.EndTime) && (entry.Expires.IsZero() || entry.Expires.After(s.clock.Now())) {
			content, rejected := s.openArchivePayload(ctx, archive.Source, entry.Payload, archiveEntryRuleARN(archive, entry), "")
			if rejected != nil {
				state, reason = "FAILED", "Internal Failure."
				break
			}
			var original eventDocument
			if err := json.Unmarshal(content, &original); err != nil {
				return err
			}
			id := identifier()
			event = &EventRecord{ID: id, WireID: id, Bus: replay.Destination, ReplayName: replay.Key.Name,
				Source: original.Source, DetailType: original.DetailType, Detail: string(original.Detail),
				Resources: original.Resources, Time: original.Time, Account: original.Account, Region: original.Region,
				Accepted: s.clock.Now(), RequestID: replay.RequestID, ActorARN: replay.ActorARN}
		}
	}
	var encryption *busEncryption
	if event != nil {
		var rejected *awswire.Error
		encryption, rejected = s.prepareBusEncryption(ctx, event.Bus, event.Source, event.DetailType, false, "")
		if rejected != nil {
			state, reason, event = "FAILED", rejected.Message, nil
		} else {
			defer clear(encryption.plain)
		}
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Replay(replay.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil || current.Version != job.Version {
			return err
		}
		if state == "FAILED" && archive.ID != "" {
			// A concurrent migration may have replaced the unavailable wrapped
			// key after selection. Retry the current payload instead of making
			// an obsolete KMS denial terminal for this replay.
			retained, err := tx.ArchiveByID(archive.ID)
			if err == nil && retained.Version != archive.Version {
				return nil
			}
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		if event != nil {
			// Archive deletion during decryption must not admit an event from
			// a source incarnation which no longer exists.
			if _, err := tx.ArchiveByID(replay.ArchiveID); errors.Is(err, ErrNotFound) {
				state, reason = "FAILED", "Archive resource not found."
			} else if err != nil {
				return err
			} else if err := commitEvent(tx, *event, s.events, s.metrics, eventSelection{FilterARNs: replay.FilterARNs, Encryption: encryption}); err != nil {
				return err
			}
		}
		current.Cursor = replay.Cursor
		current.State, current.StateReason = state, reason
		current.Version++
		current.Due = s.clock.Now()
		if state == "COMPLETED" || state == "CANCELLED" || state == "FAILED" {
			current.Finished = s.clock.Now()
		}
		return tx.PutReplay(current)
	})
}

type replayExpirationJobs struct{ s *Service }

const replayHistoryRetention = 90 * 24 * time.Hour

func (j replayExpirationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var replay ReplayRecord
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		replay, found, err = r.NextReplayExpiration()
		return err
	})
	return scheduler.Job{Key: replay.Key.ARN(), Version: replay.Version, Due: replay.Finished.Add(replayHistoryRetention)}, found, err
}

func (j replayExpirationJobs) Run(ctx context.Context, job scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		replay, found, err := tx.NextReplayExpiration()
		if err != nil || !found {
			return err
		}
		if replay.Key.ARN() != job.Key || replay.Version != job.Version || replay.Finished.Add(replayHistoryRetention).After(j.s.clock.Now()) {
			return nil
		}
		return tx.DeleteReplay(replay.Key)
	})
}
