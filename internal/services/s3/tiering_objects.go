package s3

import (
	"context"
	"time"

	"stackd/internal/awswire"
)

// New data and Lifecycle transitions start a new access window; copying or
// replicating an object never copies its source's archived access tier.
func initializeObjectTiering(object *ObjectRecord, at time.Time) {
	object.Tiering = nil
	if !object.DeleteMarker && object.StorageClass == "INTELLIGENT_TIERING" && object.Size >= 128*1024 {
		object.Tiering = &ObjectTiering{Accessed: at.UTC()}
	}
}

func objectArchiveClass(object *ObjectRecord) string {
	if isArchivedStorageClass(object.StorageClass) {
		return object.StorageClass
	}
	if object.Tiering != nil {
		switch object.Tiering.ArchiveTier {
		case ArchiveAccessTier:
			return "GLACIER"
		case DeepArchiveAccessTier:
			return "DEEP_ARCHIVE"
		}
	}
	return ""
}

// The admitted read and its access update share the existing observation
// transaction. Detached reads cannot revive deleted or replaced null versions.
func (s *Service) recordObjectRead(ctx context.Context, c *apiCall, object *ObjectRecord, wire *awswire.Error) error {
	if wire != nil || object.Tiering == nil {
		return s.record(ctx, c, wire)
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		state := ObjectTiering{Accessed: s.clock.Now().UTC()}
		if err := tx.SetObjectTiering(object.VersionKey(), object.CreatedOrder, &state); err != nil {
			return err
		}
		return s.record(tx.Context(), c, nil)
	})
}
