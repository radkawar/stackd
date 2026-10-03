package ebs

import (
	"time"

	api "stackd/internal/awsapi/ec2"
)

func (s *Service) advanceVolume(tx Transaction, volume VolumeRecord) error {
	if volume.Status == api.VolumeStateCreating && volume.Creation != nil && volume.StateMessage == "" {
		return nil
	}
	at := VolumeWorkTime(volume)
	if !volume.TransitionAt.IsZero() && volume.TransitionAt.Equal(at) {
		volume.TransitionAt = time.Time{}
		action, result := "createVolume", "available"
		if volume.Status == api.VolumeStateDeleting {
			action, result = "deleteVolume", "deleted"
			volume.Status = api.VolumeStateDeleted
		} else if volume.StateMessage != "" {
			result = "failed"
			volume.Status = api.VolumeStateDeleted
		} else {
			volume.Status = api.VolumeStateAvailable
		}
		if volume.Status == api.VolumeStateDeleted {
			if err := s.retireVolumeGrants(tx.Context(), &volume); err != nil {
				return err
			}
			if err := deleteUnpinnedVolumeBlocks(tx, volume.Key); err != nil {
				return err
			}
			if volume.Creation != nil {
				source := volume.Creation.Source
				volume.Creation = nil
				if err := tx.PutVolume(volume); err != nil {
					return err
				}
				if err := pruneLayers(tx, source.Scope); err != nil {
					return err
				}
			}
			volume.WrappedKey = nil
			volume.Modification = nil
		}
		if err := tx.PutVolume(volume); err != nil {
			return err
		}
		if err := s.publishVolumeEvent(tx.Context(), volume, action, result, at); err != nil {
			return err
		}
		if result == "failed" {
			// AWS publishes automatic deletion after a failed create, using the
			// original create request ID and an empty deletion cause.
			volume.StateMessage = ""
			return s.publishVolumeEvent(tx.Context(), volume, "deleteVolume", "deleted", at)
		}
		return nil
	}
	modification := volume.Modification
	if modification.State == api.VolumeModificationStateModifying {
		volume.Configuration = modification.Target
		modification.State = api.VolumeModificationStateOptimizing
	} else {
		modification.State = api.VolumeModificationStateCompleted
	}
	if err := tx.PutVolume(volume); err != nil {
		return err
	}
	return s.publishVolumeEvent(tx.Context(), volume, "modifyVolume", string(modification.State), at)
}
