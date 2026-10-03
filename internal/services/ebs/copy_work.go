package ebs

import (
	"context"
	"crypto/cipher"
	"errors"
	"slices"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func snapshotCopyPending(v SnapshotRecord) bool {
	return v.Copy != nil && !v.Copy.WorkAt.IsZero()
}

// advanceSnapshotCopy runs only from the effect scheduler, never the admitting
// caller's transaction. Committed destination blocks are its recovery cursor;
// source layers remain pinned until the final independent layer is published.
func (s *Service) advanceSnapshotCopy(ctx context.Context, selected SnapshotRecord) error {
	s.nativeWorkMu.Lock()
	defer s.nativeWorkMu.Unlock()
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: selected.Key.Partition, AccountID: selected.Key.AccountID, Region: selected.Key.Region,
		RequestID: selected.Copy.RequestID, ParentEventID: selected.Copy.ParentEventID,
		InvokedBy: "ec2.amazonaws.com", SourceIP: "ec2.amazonaws.com", UserAgent: "ec2.amazonaws.com",
	})
	var source, destination SnapshotRecord
	var blocks map[int32]BlockInfo
	var copied []BlockInfo
	var material BlockKeyMaterial
	var keyFailure *awswire.Error
	err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		destination, err = tx.Snapshot(selected.Key)
		if err != nil || !snapshotCopyPending(destination) || destination.Deleted {
			return err
		}
		source, err = tx.Snapshot(destination.Copy.Source)
		if err != nil {
			return err
		}
		blocks, err = resolvedBlocks(tx, source)
		if err != nil {
			return err
		}
		copied, err = tx.Blocks(destination.Key)
		if err != nil {
			return err
		}
		if source.KMSKeyARN == "" && destination.KMSKeyARN == "" {
			return nil
		}
		if s.ec2Keys == nil {
			return errors.New("EC2 snapshot copy encryption is not configured")
		}
		var keySource SnapshotRecord
		if destination.Copy.KeySource.ID != "" {
			keySource, err = tx.Snapshot(destination.Copy.KeySource)
			if err != nil {
				return err
			}
		}
		material, keyFailure = s.ec2Keys.ResumeCopy(tx.Context(), source, destination, keySource)
		if keyFailure != nil {
			return nil // Preserve the completed KMS denial before publishing failure.
		}
		destination.WrappedKey, destination.KMSKeyARN = material.WrappedKey, material.KMSKeyARN
		return tx.PutSnapshot(destination)
	})
	defer clear(material.SourcePlaintext)
	defer clear(material.DestinationPlaintext)
	if err != nil || !snapshotCopyPending(destination) {
		return err
	}
	if destination.Deleted {
		return s.finishSnapshotCopy(ctx, destination, "")
	}
	if keyFailure != nil {
		if keyFailure.StatusCode >= 500 {
			return keyFailure
		}
		return s.finishSnapshotCopy(ctx, destination, "Given key ID is not accessible")
	}
	var sourceCipher, destinationCipher cipher.AEAD
	if source.KMSKeyARN != "" {
		if len(material.SourcePlaintext) != 64 {
			return s.finishSnapshotCopy(ctx, destination, "EBS KMS source data key must contain 64 bytes")
		}
		sourceCipher, err = blockCipher(material.SourcePlaintext)
		if err != nil {
			return s.finishSnapshotCopy(ctx, destination, err.Error())
		}
	}
	if destination.KMSKeyARN != "" {
		if len(material.DestinationPlaintext) != 64 {
			return s.finishSnapshotCopy(ctx, destination, "EBS KMS destination data key must contain 64 bytes")
		}
		destinationCipher, err = blockCipher(material.DestinationPlaintext)
		if err != nil {
			return s.finishSnapshotCopy(ctx, destination, err.Error())
		}
	}
	for _, block := range copied {
		delete(blocks, block.Key.Index)
	}
	indices := make([]int32, 0, len(blocks))
	for index := range blocks {
		indices = append(indices, index)
	}
	slices.Sort(indices)
	origin := BlockEncryptionOrigin{Scope: destination.Key.Scope, ID: destination.Key.ID}
	for _, index := range indices {
		var block BlockRecord
		err = s.repository.View(ctx, func(r Reader) error {
			var err error
			block, err = r.Block(blocks[index].Key)
			return err
		})
		if err != nil {
			return err // Cancellation/storage interruption leaves resumable work.
		}
		plain, err := openBlockData(sourceCipher, block.EncryptionOrigin, index, block.Data)
		if err != nil {
			return s.finishSnapshotCopy(ctx, destination, "Snapshot copy failed: "+err.Error())
		}
		data := sealBlockData(destinationCipher, origin, index, plain)
		deleted := false
		err = s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Snapshot(destination.Key)
			if err != nil {
				return err
			}
			deleted = current.Deleted
			if deleted {
				return nil
			}
			return tx.PutBlock(BlockRecord{BlockInfo: BlockInfo{
				Key: BlockKey{Snapshot: destination.Key, Index: index}, Checksum: block.Checksum,
				WrittenSnapshotID: block.WrittenSnapshotID, EncryptionOrigin: origin,
			}, Data: data})
		})
		if sourceCipher != nil {
			clear(plain)
		}
		if err != nil {
			return err
		}
		if deleted {
			break
		}
	}
	return s.finishSnapshotCopy(ctx, destination, "")
}

func (s *Service) finishSnapshotCopy(ctx context.Context, selected SnapshotRecord, stateMessage string) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Snapshot(selected.Key)
		if err != nil || !snapshotCopyPending(current) {
			return err
		}
		if current.Copy.SourceGrantToken != "" || current.Copy.DestinationGrantToken != "" || current.Copy.DestinationEncryptGrantToken != "" {
			if s.ec2Keys == nil {
				return errors.New("EC2 snapshot copy encryption is not configured")
			}
			if rejected := s.ec2Keys.RetireCopy(tx.Context(), current); rejected != nil {
				return rejected
			}
		}
		if current.Deleted || stateMessage != "" {
			if err := tx.DeleteBlocks(current.Key); err != nil {
				return err
			}
		}
		if stateMessage != "" {
			current.StateMessage = stateMessage
		}
		current.Copy.WorkAt = time.Time{}
		current.Copy.SourceGrantToken, current.Copy.DestinationGrantToken, current.Copy.DestinationEncryptGrantToken = "", "", ""
		current.Copy.KeySource = SnapshotKey{}
		current.CompleteAt = s.clock.Now().Add(CompletionDelay)
		current.ReadableAt = current.CompleteAt.Add(ReadinessDelay)
		if err := tx.PutSnapshot(current); err != nil {
			return err
		}
		return pruneLayers(tx, current.Copy.Source.Scope)
	})
}
