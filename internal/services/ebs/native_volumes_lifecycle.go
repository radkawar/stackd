package ebs

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

func (s *Service) volumeNeedsNativeWork(v VolumeRecord) bool {
	if v.Status == api.VolumeStateCreating && v.Creation != nil {
		return true
	}
	if v.Status == api.VolumeStateDeleting {
		return v.NativePath != "" || s.nativeDisks != nil
	}
	m := v.Modification
	return v.NativePath != "" && m != nil && m.State == api.VolumeModificationStateModifying && m.Original.Size != m.Target.Size
}

// advanceNativeWork is only called by the scheduler outside repository callbacks.
// Ordinary API eager advancement remains metadata-only.
func (s *Service) advanceNativeWork(ctx context.Context) error {
	for {
		var snapshot SnapshotRecord
		var volume VolumeRecord
		err := s.repository.View(ctx, func(r Reader) error { var err error; snapshot, volume, err = nextEBSWork(r); return err })
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if volume.Key.ID != "" {
			if VolumeWorkTime(volume).After(s.clock.Now()) {
				return nil
			}
			if s.volumeNeedsNativeWork(volume) {
				if err := s.advanceNativeVolume(ctx, volume); err != nil {
					return err
				}
			} else if err := s.advance(ctx); err != nil {
				return err
			}
		} else {
			if workTime(snapshot).After(s.clock.Now()) {
				return nil
			}
			if snapshotCopyPending(snapshot) {
				if err := s.advanceSnapshotCopy(ctx, snapshot); err != nil {
					return err
				}
			} else if volumeSnapshotBlocksPending(snapshot) {
				if err := s.advanceVolumeSnapshotBlocks(ctx, snapshot); err != nil {
					return err
				}
			} else if snapshot.Volume != nil && snapshot.Volume.NativeBackupPath != "" {
				if err := s.advanceNativeSnapshot(ctx, snapshot); err != nil {
					return err
				}
			} else if err := s.advance(ctx); err != nil {
				return err
			}
		}
	}
}

func (s *Service) advanceNativeVolume(ctx context.Context, selected VolumeRecord) error {
	requestID, parentEventID := selected.RequestID, selected.ParentEventID
	if selected.Status != api.VolumeStateDeleting && selected.Modification != nil {
		requestID, parentEventID = selected.Modification.RequestID, selected.Modification.ParentEventID
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: selected.Key.Partition, AccountID: selected.Key.AccountID, Region: selected.Key.Region, RequestID: requestID, ParentEventID: parentEventID, InvokedBy: "ec2.amazonaws.com", SourceIP: "ec2.amazonaws.com", UserAgent: "ec2.amazonaws.com"})
	// A process interruption can leave a ready temporary snapshot backup. Import
	// and release it before removing the source's grants or native disk.
	if selected.Status == api.VolumeStateDeleting {
		var snapshots []SnapshotRecord
		if err := s.repository.View(ctx, func(r Reader) error { var err error; snapshots, err = r.Snapshots(selected.Key.Scope); return err }); err != nil {
			return err
		}
		for _, snapshot := range snapshots {
			if snapshot.Volume != nil && snapshot.Volume.Source == selected.Key && snapshot.Volume.NativeBackupPath != "" {
				if err := s.advanceNativeSnapshot(ctx, snapshot); err != nil {
					return err
				}
			}
		}
	}
	s.nativeWorkMu.Lock()
	defer s.nativeWorkMu.Unlock()
	var v VolumeRecord
	err := s.repository.View(ctx, func(r Reader) error { var err error; v, err = r.Volume(selected.Key); return err })
	if err != nil {
		return err
	}
	if !s.volumeNeedsNativeWork(v) || VolumeWorkTime(v).After(s.clock.Now()) {
		return nil
	}
	if v.Status == api.VolumeStateCreating {
		return s.hydrateVolumeCreation(ctx, v)
	}
	if v.Status == api.VolumeStateDeleting {
		if err := s.deleteNativeVolume(ctx, v); err != nil {
			return err
		}
		return s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Volume(v.Key)
			if err != nil {
				return err
			}
			if current.Status != api.VolumeStateDeleting {
				return errors.New("volume deletion changed during native cleanup")
			}
			current.NativePath = ""
			return s.advanceVolume(tx, current)
		})
	}
	if s.nativeDisks == nil {
		return errors.New("native EBS disk storage is not configured")
	}
	disk := nativeVolumeDisk(v)
	var effectErr error
	err = s.repository.Update(ctx, func(tx Transaction) error {
		if !v.Encrypted {
			return nil
		}
		if s.instanceKeys == nil {
			return errors.New("instance EBS encryption is not configured")
		}
		plain, failure := s.instanceKeys.DecryptServiceVolume(tx.Context(), v)
		disk.Key = plain
		if failure != nil {
			effectErr = failure
		} else if len(plain) != 64 {
			effectErr = errors.New("EBS KMS data key must contain 64 bytes")
		}
		return nil
	})
	defer clear(disk.Key)
	if err != nil {
		return err
	}
	if effectErr == nil {
		effectErr = s.nativeDisks.ResizeDisk(ctx, disk, int64(v.Modification.Target.Size)<<30)
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Volume(v.Key)
		if err != nil {
			return err
		}
		if current.Modification == nil || !current.Modification.Started.Equal(v.Modification.Started) || current.Modification.State != api.VolumeModificationStateModifying {
			return errors.New("volume modification changed during native resize")
		}
		if effectErr != nil {
			current.Modification.State = api.VolumeModificationStateFailed
			current.Modification.StatusMessage = effectErr.Error()
			current.Modification.CompletedAt = s.clock.Now()
			if err := tx.PutVolume(current); err != nil {
				return err
			}
			return s.publishVolumeEvent(tx.Context(), current, "modifyVolume", "failed", s.clock.Now())
		}
		return s.advanceVolume(tx, current)
	})
}
