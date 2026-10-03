package ebs

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/ebs"
	"stackd/internal/scheduler"
)

func lifecycleTime(v SnapshotRecord) time.Time {
	if snapshotCopyPending(v) || volumeSnapshotBlocksPending(v) {
		return time.Time{}
	}
	if v.Deleted {
		return v.DeleteAt
	}
	if v.Status == api.StatusERROR {
		return time.Time{}
	}
	if v.Status == api.StatusPENDING {
		if v.Sealed {
			return v.CompleteAt
		}
		return v.TimeoutAt
	}
	if !v.Readable {
		return v.ReadableAt
	}
	return time.Time{}
}

func workTime(v SnapshotRecord) time.Time {
	if snapshotCopyPending(v) {
		return v.Copy.WorkAt
	}
	if volumeSnapshotBlocksPending(v) {
		return v.Volume.BlocksWorkAt
	}
	due := lifecycleTime(v)
	if v.Volume != nil && v.Volume.NativeBackupPath != "" && !v.Volume.NativeWorkAt.IsZero() {
		return v.Volume.NativeWorkAt
	}
	if !v.Deleted && !v.SharingAt.IsZero() && (due.IsZero() || v.SharingAt.Before(due)) {
		return v.SharingAt
	}
	return due
}

type snapshotJobs struct{ s *Service }

// nextEBSWork chooses one owner transition by its service-time deadline. Both
// resource kinds share the driver and the transaction, not separate wall clocks.
func nextEBSWork(r Reader) (SnapshotRecord, VolumeRecord, error) {
	snapshot, snapshotErr := r.NextWork()
	if snapshotErr != nil && !errors.Is(snapshotErr, ErrNotFound) {
		return SnapshotRecord{}, VolumeRecord{}, snapshotErr
	}
	volume, volumeErr := r.NextVolumeWork()
	if volumeErr != nil && !errors.Is(volumeErr, ErrNotFound) {
		return SnapshotRecord{}, VolumeRecord{}, volumeErr
	}
	if snapshotErr != nil && volumeErr != nil {
		return SnapshotRecord{}, VolumeRecord{}, ErrNotFound
	}
	if volumeErr == nil && (snapshotErr != nil || VolumeWorkTime(volume).Before(workTime(snapshot))) {
		return SnapshotRecord{}, volume, nil
	}
	return snapshot, VolumeRecord{}, nil
}

func (j snapshotJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	err := j.s.repository.View(ctx, func(r Reader) error {
		snapshot, volume, err := nextEBSWork(r)
		if err != nil {
			return err
		}
		if volume.Key.ID != "" {
			job = scheduler.Job{Key: volumeARN(volume.Key), Due: VolumeWorkTime(volume)}
		} else {
			job = scheduler.Job{Key: snapshotARN(snapshot.Key) + ":" + snapshot.Key.AccountID, Due: workTime(snapshot)}
		}
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		return scheduler.Job{}, false, nil
	}
	return job, err == nil, err
}

func (j snapshotJobs) Run(ctx context.Context, _ scheduler.Job) error {
	return j.s.advanceNativeWork(ctx)
}

func (s *Service) advance(ctx context.Context) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		for {
			snapshot, volume, err := nextEBSWork(tx)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			now := s.clock.Now()
			if volume.Key.ID != "" {
				if VolumeWorkTime(volume).After(now) {
					return nil
				}
				if s.volumeNeedsNativeWork(volume) {
					return nil
				}
				if err := s.advanceVolume(tx, volume); err != nil {
					return err
				}
			} else {
				if workTime(snapshot).After(now) {
					return nil
				}
				if snapshotCopyPending(snapshot) || volumeSnapshotBlocksPending(snapshot) || (snapshot.Volume != nil && snapshot.Volume.NativeBackupPath != "") {
					return nil
				}
				if err := s.advanceSnapshot(tx, snapshot, now); err != nil {
					return err
				}
			}
		}
	})
}

func (s *Service) advanceSnapshot(tx Transaction, v SnapshotRecord, now time.Time) error {
	lifecycleDue := lifecycleTime(v)
	lifecycleReady := !lifecycleDue.IsZero() && !lifecycleDue.After(now)
	completed := lifecycleReady && !v.Deleted && v.Status == api.StatusPENDING
	if !v.Deleted && !v.SharingAt.IsZero() && !v.SharingAt.After(now) {
		shares := v.Shares[:0]
		for _, share := range v.Shares {
			if share.Granted {
				share.Readable = true
				shares = append(shares, share)
			}
		}
		v.Shares = shares
		v.SharingAt = time.Time{}
	}
	if lifecycleReady && v.Deleted {
		v.DeleteAt = time.Time{}
		if err := tx.PutSnapshot(v); err != nil {
			return err
		}
		if err := pruneLayers(tx, v.Key.Scope); err != nil {
			return err
		}
		s.admission.forget(v.Key)
		return nil
	}
	if lifecycleReady && v.Status == api.StatusPENDING {
		if !v.Sealed {
			v.Status = api.StatusERROR
			v.StateMessage = "Snapshot timed out"
		} else if v.StateMessage != "" {
			v.Status = api.StatusERROR
		} else {
			v.Status = api.StatusCOMPLETED
		}
	} else if lifecycleReady {
		v.Readable = true
	}
	if err := tx.PutSnapshot(v); err != nil {
		return err
	}
	if completed {
		if v.Copy != nil {
			return s.publishCopySnapshotEvent(tx.Context(), v, lifecycleDue)
		}
		if v.Volume != nil {
			return s.publishVolumeSnapshotEvent(tx.Context(), v, lifecycleDue)
		}
	}
	return nil
}
func pruneLayers(tx Transaction, scope Scope) error {
	records, err := tx.Snapshots(scope)
	if err != nil {
		return err
	}
	sources, err := tx.PendingSnapshotSources(scope)
	if err != nil {
		return err
	}
	pending := make(map[string]bool, len(sources))
	for _, source := range sources {
		pending[source.ID] = true
	}
	byID := map[string]SnapshotRecord{}
	for _, record := range records {
		byID[record.Key.ID] = record
	}
	retained := map[string]bool{}
	for _, record := range records {
		if record.Deleted && record.DeleteAt.IsZero() && !pending[record.Key.ID] {
			continue
		}
		for {
			if retained[record.Key.ID] {
				break
			}
			retained[record.Key.ID] = true
			if record.ParentID == "" {
				break
			}
			parent, ok := byID[record.ParentID]
			if !ok {
				return errors.New("missing EBS snapshot parent layer")
			}
			record = parent
		}
	}
	for _, record := range records {
		if record.Deleted && !retained[record.Key.ID] {
			if err = tx.DeleteBlocks(record.Key); err != nil {
				return err
			}
		}
	}
	return nil
}
