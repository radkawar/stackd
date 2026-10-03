package ebs

import (
	"context"
	"crypto/cipher"
	"errors"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// hydrateVolumeCreation runs under nativeWorkMu, never inside an admission
// transaction. Existing block rows are its resume point; a crash can repeat only
// an uncommitted block. The admitted source remains pinned until the final commit.
func (s *Service) hydrateVolumeCreation(ctx context.Context, volume VolumeRecord) error {
	if volume.Creation == nil || volume.Status != api.VolumeStateCreating {
		return nil
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: volume.Key.Partition, AccountID: volume.Key.AccountID, Region: volume.Key.Region, RequestID: volume.RequestID, ParentEventID: volume.ParentEventID, InvokedBy: "ec2.amazonaws.com", SourceIP: "ec2.amazonaws.com", UserAgent: "ec2.amazonaws.com"})
	var source SnapshotRecord
	var blocks map[int32]BlockInfo
	var written []VolumeBlockInfo
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		source, err = r.Snapshot(volume.Creation.Source)
		if err != nil {
			return err
		}
		blocks, err = resolvedBlocks(r, source)
		if err != nil {
			return err
		}
		written, err = r.VolumeBlocks(volume.Key)
		return err
	})
	if err != nil {
		return err
	}
	for _, block := range written {
		delete(blocks, block.Key.Index)
	}
	var material BlockKeyMaterial
	var sourceCipher, destinationCipher cipher.AEAD
	if (len(blocks) != 0 || len(written) == 0) && volume.Encrypted && !volume.Creation.ReuseSourceCiphertext {
		if s.ec2Keys == nil {
			return errors.New("EC2 volume encryption is not configured")
		}
		var rejected error
		err = s.repository.Update(ctx, func(tx Transaction) error {
			keys, rejection := s.ec2Keys.ResumeVolume(tx.Context(), volume)
			material = keys
			if rejection != nil {
				rejected = rejection
			}
			return nil
		})
		defer clear(material.SourcePlaintext)
		defer clear(material.DestinationPlaintext)
		if err != nil {
			return err
		}
		if rejected != nil {
			return s.finishVolumeCreation(ctx, volume, rejected)
		}
		destinationCipher, err = blockCipher(material.DestinationPlaintext)
		if err == nil && source.KMSKeyARN != "" {
			sourceCipher, err = blockCipher(material.SourcePlaintext)
		}
		if err != nil {
			return s.finishVolumeCreation(ctx, volume, err)
		}
	}
	for index, info := range blocks {
		var block BlockRecord
		var active bool
		err = s.repository.View(ctx, func(r Reader) error {
			current, err := r.Volume(volume.Key)
			if err != nil {
				return err
			}
			active = current.Status == api.VolumeStateCreating && current.Creation != nil
			if !active {
				return nil
			}
			block, err = r.Block(info.Key)
			return err
		})
		if err != nil || !active {
			return err
		}
		origin, data := block.EncryptionOrigin, block.Data
		if !volume.Creation.ReuseSourceCiphertext {
			plain, err := openBlockData(sourceCipher, origin, index, data)
			if err != nil {
				clear(block.Data)
				return s.finishVolumeCreation(ctx, volume, err)
			}
			origin = BlockEncryptionOrigin{Scope: volume.Key.Scope, ID: volume.Key.ID}
			data = sealBlockData(destinationCipher, origin, index, plain)
			if sourceCipher != nil {
				clear(plain)
			}
		}
		err = s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Volume(volume.Key)
			if err != nil {
				return err
			}
			active = current.Status == api.VolumeStateCreating && current.Creation != nil
			if !active {
				return nil
			}
			return tx.PutVolumeBlock(VolumeBlockRecord{VolumeBlockInfo: VolumeBlockInfo{
				Key: VolumeBlockKey{Volume: volume.Key, Index: index}, Checksum: block.Checksum,
				WrittenSnapshotID: block.WrittenSnapshotID, EncryptionOrigin: origin,
			}, Data: data})
		})
		clear(data)
		clear(block.Data)
		if err != nil || !active {
			return err
		}
	}
	return s.finishVolumeCreation(ctx, volume, nil)
}

func (s *Service) finishVolumeCreation(ctx context.Context, volume VolumeRecord, failure error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Volume(volume.Key)
		if err != nil {
			return err
		}
		if current.Status != api.VolumeStateCreating || current.Creation == nil {
			return nil
		}
		source := current.Creation.Source
		if current.Creation.RetireGrant && current.ServiceGrantID != "" {
			if s.ec2Keys == nil {
				return errors.New("EC2 volume encryption is not configured")
			}
			if rejected := s.ec2Keys.RetireVolumeCreationGrant(tx.Context(), current); rejected != nil {
				return rejected
			}
			current.ServiceGrantID = ""
		}
		if failure != nil {
			current.StateMessage = failure.Error()
			var rejected *awswire.Error
			if current.Creation.RetireGrant && errors.As(failure, &rejected) {
				current.StateMessage = rejected.Message
			}
		}
		current.Creation = nil
		if err := tx.PutVolume(current); err != nil {
			return err
		}
		if err := pruneLayers(tx, source.Scope); err != nil {
			return err
		}
		if !current.TransitionAt.After(s.clock.Now()) {
			return s.advanceVolume(tx, current)
		}
		return nil
	})
}
