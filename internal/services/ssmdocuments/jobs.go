package ssmdocuments

import (
	"context"
	"encoding/json"
	"errors"

	"stackd/internal/scheduler"
)

// Admission validates content synchronously. ReadyAt is the accepting service
// instant: this job models a committed observation boundary, not AWS latency.
// Status belongs to each version; activating a new version does not move default.
type activationJobs struct{ s *Service }
type activationKey struct {
	Key        VersionKey
	DocumentID string
}

func (source activationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var pending Activation
	err := source.s.repository.View(ctx, func(r Reader) error {
		var err error
		pending, err = r.NextActivation()
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	key, err := json.Marshal(activationKey{pending.Key, pending.DocumentID})
	return scheduler.Job{Key: string(key), Version: uint64(pending.Key.Version), Due: pending.Due}, err == nil, err
}

func (source activationJobs) Run(ctx context.Context, job scheduler.Job) error {
	var key activationKey
	if err := json.Unmarshal([]byte(job.Key), &key); err != nil {
		return err
	}
	return source.s.repository.Update(ctx, func(tx Transaction) error {
		record, err := tx.Document(key.Key.Document)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if record.DocumentID != key.DocumentID || uint64(key.Key.Version) != job.Version {
			return nil
		}
		version, err := tx.Version(key.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !pendingStatus(version.Status) || !version.ReadyAt.Equal(job.Due) || version.ReadyAt.After(source.s.clock.Now()) {
			return nil
		}
		return tx.ActivateVersion(version.Key)
	})
}

func pendingStatus(status string) bool { return status == "Creating" || status == "Updating" }
