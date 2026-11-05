package s3tables

import (
	"context"

	domain "stackd/internal/services/s3tables"
	"stackd/storage/memory"
)

func (r *memoryObjects) Info(ctx context.Context, warehouse, key string) (domain.ObjectInfo, error) {
	var info domain.ObjectInfo
	err := r.store.View(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(false); err != nil {
			return err
		}
		object, ok := s.objects[warehouse][key]
		if !ok {
			return domain.ErrNotFound
		}
		info = domain.CloneObjectInfo(object.info)
		return nil
	})
	return info, err
}
