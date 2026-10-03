package ebs

import (
	"context"
	"errors"
	"fmt"
	"time"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

func volumeSnapshotBlocksPending(v SnapshotRecord) bool {
	return v.Volume != nil && !v.Volume.BlocksWorkAt.IsZero()
}

// deleteUnpinnedVolumeBlocks is the shared removal edge for deletion and native
// handoff. Available standalone blocks cannot change after admission; retaining
// them preserves that capture point even when the volume's current authority moves.
func deleteUnpinnedVolumeBlocks(tx Transaction, key VolumeKey) error {
	pending, err := tx.VolumeSnapshotBlocksPending(key)
	if err != nil || pending {
		return err
	}
	return tx.DeleteVolumeBlocks(key)
}

// advanceVolumeSnapshotBlocks transfers one detached payload per transaction.
// Committed snapshot block rows are its restart cursor. The source pin remains
// until publication or discard, independently of source visibility and authority.
func (s *Service) advanceVolumeSnapshotBlocks(ctx context.Context, selected SnapshotRecord) error {
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: selected.Key.Partition, AccountID: selected.Key.AccountID, Region: selected.Key.Region,
		RequestID: selected.Volume.RequestID, ParentEventID: selected.Volume.ParentEventID,
		InvokedBy: "ec2.amazonaws.com", SourceIP: "ec2.amazonaws.com", UserAgent: "ec2.amazonaws.com",
	})
	var destination SnapshotRecord
	var blocks []VolumeBlockInfo
	var written []BlockInfo
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		destination, err = r.Snapshot(selected.Key)
		if err != nil || !volumeSnapshotBlocksPending(destination) || destination.Deleted {
			return err
		}
		blocks, err = r.VolumeBlocks(destination.Volume.Source)
		if err != nil {
			return err
		}
		written, err = r.Blocks(destination.Key)
		return err
	})
	if err != nil || !volumeSnapshotBlocksPending(destination) {
		return err
	}
	if destination.Deleted {
		return s.finishVolumeSnapshotBlocks(ctx, destination, nil)
	}
	copied := make(map[int32]bool, len(written))
	for _, info := range written {
		copied[info.Key.Index] = true
	}
	for _, info := range blocks {
		if copied[info.Key.Index] {
			continue
		}
		var block VolumeBlockRecord
		var active bool
		err = s.repository.View(ctx, func(r Reader) error {
			current, err := r.Snapshot(destination.Key)
			if err != nil {
				return err
			}
			active = volumeSnapshotBlocksPending(current) && !current.Deleted
			if !active {
				return nil
			}
			block, err = r.VolumeBlock(info.Key)
			return err
		})
		if errors.Is(err, ErrNotFound) {
			return s.finishVolumeSnapshotBlocks(ctx, destination, fmt.Errorf("Volume snapshot failed: %w", err))
		}
		if err != nil {
			return err // Cancellation or storage interruption leaves resumable work.
		}
		if !active {
			return s.finishVolumeSnapshotBlocks(ctx, destination, nil)
		}
		err = s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Snapshot(destination.Key)
			if err != nil {
				return err
			}
			active = volumeSnapshotBlocksPending(current) && !current.Deleted
			if !active {
				return nil
			}
			// The snapshot owns the admitted wrapped key. Ciphertext and its
			// authenticated origin move unchanged; no decrypt or new grant is needed.
			return tx.PutBlock(BlockRecord{BlockInfo: BlockInfo{
				Key: BlockKey{Snapshot: destination.Key, Index: info.Key.Index}, Checksum: block.Checksum,
				WrittenSnapshotID: block.WrittenSnapshotID, EncryptionOrigin: block.EncryptionOrigin,
			}, Data: block.Data})
		})
		clear(block.Data)
		if err != nil {
			return err
		}
		if !active {
			break
		}
	}
	return s.finishVolumeSnapshotBlocks(ctx, destination, nil)
}

func (s *Service) finishVolumeSnapshotBlocks(ctx context.Context, selected SnapshotRecord, cause error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Snapshot(selected.Key)
		if err != nil || !volumeSnapshotBlocksPending(current) {
			return err
		}
		current.Sealed = true
		current.Volume.BlocksWorkAt = time.Time{}
		if current.Deleted || cause != nil {
			if err := tx.DeleteBlocks(current.Key); err != nil {
				return err
			}
			current.CompleteAt, current.ReadableAt = s.clock.Now(), time.Time{}
			if cause != nil {
				current.StateMessage = cause.Error()
			} else {
				current.StateMessage = "Snapshot deleted"
			}
		} else {
			current.CompleteAt = s.clock.Now().Add(CompletionDelay)
			current.ReadableAt = current.CompleteAt.Add(ReadinessDelay)
		}
		if err := tx.PutSnapshot(current); err != nil {
			return err
		}
		source, err := tx.Volume(current.Volume.Source)
		if err != nil {
			return err
		}
		if source.NativePath != "" || source.Status == api.VolumeStateDeleted {
			return deleteUnpinnedVolumeBlocks(tx, source.Key)
		}
		return nil
	})
}
