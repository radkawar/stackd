package ebs

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	native "stackd/compute/ec2"
	ebsapi "stackd/internal/awsapi/ebs"
	"stackd/internal/awsctx"
)

func nativeSnapshotDisk(v SnapshotRecord) native.Disk {
	return native.Disk{ID: snapshotARN(v.Key) + ":" + v.Key.AccountID, Path: v.Volume.NativeBackupPath, Encrypted: v.KMSKeyARN != ""}
}

// captureNativeSnapshots requires nativeWorkMu. A group uses one native QMP
// transaction; sequential disk backup is not multi-volume crash consistency.
func (s *Service) captureNativeSnapshots(ctx context.Context, records []SnapshotRecord) error {
	var pending []SnapshotRecord
	for _, v := range records {
		if v.Volume != nil && v.Volume.NativeBackupPath != "" {
			pending = append(pending, v)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	sources := make([]native.Disk, len(pending))
	targets := make([]native.Disk, len(pending))
	defer func() {
		for i := range sources {
			clear(sources[i].Key)
			clear(targets[i].Key)
		}
	}()
	fail := func(cause error) error {
		var joined error
		for _, v := range pending {
			joined = errors.Join(joined, s.failNativeSnapshot(ctx, v, cause))
		}
		return errors.Join(cause, joined)
	}
	for i, v := range pending {
		var source VolumeRecord
		var keyFailure error
		err := s.repository.Update(ctx, func(tx Transaction) error {
			var err error
			source, err = tx.Volume(v.Volume.Source)
			if err != nil {
				return err
			}
			current, err := tx.Snapshot(v.Key)
			if err != nil {
				return err
			}
			if current.Deleted {
				return errors.New("snapshot deleted before native capture")
			}
			current.Volume.NativeWorkAt = s.clock.Now()
			if err := tx.PutSnapshot(current); err != nil {
				return err
			}
			if source.Encrypted {
				if s.instanceKeys == nil {
					return errors.New("instance service keys are not configured")
				}
				plain, denied := s.instanceKeys.DecryptServiceVolume(tx.Context(), source)
				if denied != nil {
					clear(plain)
					keyFailure = denied
				} else if len(plain) != 64 {
					clear(plain)
					keyFailure = errors.New("EBS KMS data key must contain 64 bytes")
				} else {
					sources[i].Key = plain
				}
			}
			return nil
		})
		if err != nil {
			return fail(err)
		}
		if keyFailure != nil {
			return fail(keyFailure)
		}
		sources[i].ID = volumeARN(source.Key)
		sources[i].Path = source.NativePath
		sources[i].Encrypted = source.Encrypted
		targets[i] = nativeSnapshotDisk(v)
		targets[i].Key = sources[i].Key
	}
	var err error
	results := make([]native.BackupResult, len(pending))
	if len(pending) == 1 {
		results[0], err = s.nativeDisks.Backup(ctx, sources[0], targets[0])
	} else {
		results, err = s.nativeDisks.BackupDisks(ctx, sources, targets)
	}
	if err != nil {
		return fail(err)
	}
	if len(results) != len(pending) {
		return fail(errors.New("native backup did not return every image disk"))
	}
	// The independent native files now own immutable bytes. Persist readiness
	// before any block transfer, so restart can resume without recapturing.
	err = s.repository.Update(ctx, func(tx Transaction) error {
		for i := range pending {
			v, e := tx.Snapshot(pending[i].Key)
			if e != nil {
				return e
			}
			v.Volume.NativeBackupReady = true
			v.Volume.NativeWorkAt = s.clock.Now()
			pending[i] = v
			if e := tx.PutSnapshot(v); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i, v := range pending {
		if err := s.publishNativeSnapshot(ctx, v, targets[i], results[i]); err != nil {
			return fail(err)
		}
	}
	return nil
}

func (s *Service) advanceNativeSnapshot(ctx context.Context, admitted SnapshotRecord) error {
	s.nativeWorkMu.Lock()
	defer s.nativeWorkMu.Unlock()
	return s.resumeNativeSnapshot(ctx, admitted)
}

func (s *Service) resumeNativeSnapshot(ctx context.Context, admitted SnapshotRecord) error {
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: admitted.Key.Partition, AccountID: admitted.Key.AccountID, Region: admitted.Key.Region,
		RequestID: admitted.Volume.RequestID, ParentEventID: admitted.Volume.ParentEventID, InvokedBy: "ec2.amazonaws.com", SourceIP: "ec2.amazonaws.com", UserAgent: "ec2.amazonaws.com"})
	var v SnapshotRecord
	if err := s.repository.View(ctx, func(r Reader) error { var err error; v, err = r.Snapshot(admitted.Key); return err }); err != nil {
		return err
	}
	if v.Volume == nil || v.Volume.NativeBackupPath == "" {
		return nil
	}
	if s.nativeDisks == nil {
		return errors.New("native EBS disk storage is not configured")
	}
	if v.Sealed || v.Deleted {
		return s.cleanupNativeSnapshot(ctx, v)
	}
	if !v.Volume.NativeBackupReady {
		return s.failNativeSnapshot(ctx, v, errors.New("native snapshot capture interrupted before completion; the original capture point cannot be recovered"))
	}
	disk := nativeSnapshotDisk(v)
	defer func() { clear(disk.Key) }()
	if disk.Encrypted {
		var keyFailure error
		err := s.repository.Update(ctx, func(tx Transaction) error {
			source, err := tx.Volume(v.Volume.Source)
			if err != nil {
				return err
			}
			if s.instanceKeys == nil {
				return errors.New("instance service keys are not configured")
			}
			plain, denied := s.instanceKeys.DecryptServiceVolume(tx.Context(), source)
			if denied != nil {
				clear(plain)
				keyFailure = denied
				return nil
			}
			if len(plain) != 64 {
				clear(plain)
				keyFailure = errors.New("EBS KMS data key must contain 64 bytes")
				return nil
			}
			disk.Key = plain
			return nil
		})
		if err != nil {
			return s.failNativeSnapshot(ctx, v, err)
		}
		if keyFailure != nil {
			return s.failNativeSnapshot(ctx, v, keyFailure)
		}
	}
	if err := s.publishNativeSnapshot(ctx, v, disk, native.BackupResult{}); err != nil {
		return s.failNativeSnapshot(ctx, v, err)
	}
	return nil
}

func (s *Service) publishNativeSnapshot(ctx context.Context, v SnapshotRecord, disk native.Disk, capture native.BackupResult) error {
	var aead cipher.AEAD
	if disk.Encrypted {
		var err error
		aead, err = blockCipher(disk.Key)
		if err != nil {
			return err
		}
	}
	extents := capture.Extents
	var err error
	if !capture.ExtentsKnown {
		extents, err = s.nativeDisks.Allocated(ctx, disk)
		if err != nil {
			return err
		}
	}
	slices.SortFunc(extents, func(a, b native.Extent) int {
		if a.Start < b.Start {
			return -1
		}
		if a.Start > b.Start {
			return 1
		}
		return 0
	})
	buffer := make([]byte, BlockSize)
	defer clear(buffer)
	last := int64(-1)
	size := v.VolumeSize << 30
	origin := BlockEncryptionOrigin{Scope: v.Key.Scope, ID: v.Key.ID}
	err = s.nativeDisks.ReadDisk(ctx, disk, func(reader io.ReaderAt) error {
		for _, extent := range extents {
			if extent.Start < 0 || extent.Length < 0 || extent.Start > size || extent.Length > size-extent.Start {
				return errors.New("native snapshot extent exceeds volume size")
			}
			if !extent.Data || extent.Zero || extent.Length == 0 {
				continue
			}
			first := extent.Start / BlockSize
			end := (extent.Start + extent.Length - 1) / BlockSize
			for index := max(first, last+1); index <= end; index++ {
				if _, err := reader.ReadAt(buffer, index*BlockSize); err != nil {
					return err
				}
				checksum := sha256.Sum256(buffer)
				data := sealBlockData(aead, origin, int32(index), buffer)
				block := BlockRecord{BlockInfo: BlockInfo{Key: BlockKey{Snapshot: v.Key, Index: int32(index)}, Checksum: checksum, WrittenSnapshotID: v.Key.ID, EncryptionOrigin: origin}, Data: data}
				err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutBlock(block) })
				if aead != nil {
					clear(data)
				}
				clear(buffer)
				if err != nil {
					return err
				}
				last = index
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Snapshot(v.Key)
		if err != nil {
			return err
		}
		if current.Deleted {
			return errors.New("snapshot deleted during native publication")
		}
		current.Sealed = true
		current.CompleteAt = s.clock.Now().Add(CompletionDelay)
		current.ReadableAt = current.CompleteAt.Add(ReadinessDelay)
		current.Volume.NativeWorkAt = s.clock.Now()
		v = current
		return tx.PutSnapshot(current)
	})
	if err != nil {
		return err
	}
	return s.cleanupNativeSnapshot(ctx, v)
}

func (s *Service) failNativeSnapshot(ctx context.Context, v SnapshotRecord, cause error) error {
	completion, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	err := s.repository.Update(completion, func(tx Transaction) error {
		current, err := tx.Snapshot(v.Key)
		if err != nil {
			return err
		}
		if current.Sealed {
			v = current
			return nil
		}
		current.Sealed = true
		current.StateMessage = fmt.Sprintf("Native snapshot failed: %v", cause)
		current.CompleteAt = s.clock.Now()
		current.ReadableAt = time.Time{}
		current.Volume.NativeWorkAt = s.clock.Now()
		v = current
		if err := tx.DeleteBlocks(v.Key); err != nil {
			return err
		}
		return tx.PutSnapshot(current)
	})
	if err != nil {
		return err
	}
	return s.cleanupNativeSnapshot(completion, v)
}

func (s *Service) cleanupNativeSnapshot(ctx context.Context, v SnapshotRecord) error {
	if v.Volume.NativeBackupPath == "" {
		return nil
	}
	if err := s.nativeDisks.DeleteDisk(ctx, nativeSnapshotDisk(v)); err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Snapshot(v.Key)
		if err != nil {
			return err
		}
		current.Volume.NativeBackupPath = ""
		current.Volume.NativeBackupReady = false
		current.Volume.NativeWorkAt = time.Time{}
		if current.Deleted && current.Status == ebsapi.StatusPENDING {
			current.Sealed = true
			current.StateMessage = "Snapshot deleted"
		}
		return tx.PutSnapshot(current)
	})
}
