package s3tables

import (
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	domain "stackd/internal/services/s3tables"
	"stackd/storage/internal/s3tablescrypt"
	"stackd/storage/memory"
)

// WarehouseObjects stores private bytes; authorization belongs to S3 Tables.
type WarehouseObjects = domain.WarehouseObjects
type ObjectInfo = domain.ObjectInfo

type warehouseObject struct {
	info domain.ObjectInfo
	data s3tablescrypt.Envelope
}
type uploadKey struct{ warehouse, key, id string }
type warehouseUpload struct {
	info  domain.MultipartUpload
	parts map[int]warehousePart
}
type warehousePart struct {
	info domain.MultipartPart
	data s3tablescrypt.Envelope
}
type warehouseState struct {
	objects map[string]map[string]warehouseObject
	uploads map[uploadKey]warehouseUpload
}
type memoryObjects struct{ store *memory.Store[warehouseState] }

func NewMemoryObjects(d *memory.Domain) WarehouseObjects {
	initial := warehouseState{objects: make(map[string]map[string]warehouseObject), uploads: make(map[uploadKey]warehouseUpload)}
	return &memoryObjects{store: memory.New(d, initial, func(s warehouseState) warehouseState {
		return warehouseState{objects: maps.Clone(s.objects), uploads: maps.Clone(s.uploads)}
	})}
}
func publicationGuard(ctx context.Context, guard domain.PublicationGuard) error {
	if guard != nil {
		return guard(ctx)
	}
	return nil
}
func (r *memoryObjects) Read(ctx context.Context, warehouse, key string) ([]byte, error) {
	data, _, err := r.ReadObject(ctx, warehouse, key)
	return data, err
}
func (r *memoryObjects) ReadObject(ctx context.Context, warehouse, key string) ([]byte, domain.ObjectInfo, error) {
	var data []byte
	var info domain.ObjectInfo
	err := r.store.View(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(false); err != nil {
			return err
		}
		object, ok := s.objects[warehouse][key]
		if !ok {
			return domain.ErrNotFound
		}
		var err error
		data, err = object.data.Open(nil, s3tablescrypt.ObjectIdentity(warehouse, key), object.info.Size)
		if err != nil {
			return err
		}
		info = domain.CloneObjectInfo(object.info)
		return nil
	})
	return data, info, err
}
func (r *memoryObjects) Write(ctx context.Context, warehouse, key string, data []byte, modified time.Time) error {
	info, err := domain.SingleObjectInfo(key, data, domain.ObjectAttributes{}, modified)
	if err != nil {
		return err
	}
	_, err = r.WriteObject(ctx, warehouse, data, info, domain.ObjectConditions{}, nil)
	return err
}
func putMemoryObject(s *warehouseState, warehouse string, object warehouseObject) {
	objects := maps.Clone(s.objects[warehouse])
	if objects == nil {
		objects = make(map[string]warehouseObject)
	}
	objects[object.info.Key] = object
	s.objects[warehouse] = objects
}
func (r *memoryObjects) WriteObject(ctx context.Context, warehouse string, data []byte, info domain.ObjectInfo, conditions domain.ObjectConditions, guard domain.PublicationGuard) (domain.ObjectInfo, error) {
	info = domain.CloneObjectInfo(info)
	err := r.store.Update(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(true); err != nil {
			return err
		}
		_, exists := s.objects[warehouse][info.Key]
		// Revoked authority must not be masked by an existing destination.
		if err := publicationGuard(tx.Context(), guard); err != nil {
			return err
		}
		if err := domain.CheckObjectConditions(exists, conditions); err != nil {
			return err
		}
		encrypted, err := s3tablescrypt.Seal(data, s3tablescrypt.ObjectIdentity(warehouse, info.Key))
		if err != nil {
			return err
		}
		putMemoryObject(s, warehouse, warehouseObject{info: info, data: encrypted})
		return publicationGuard(tx.Context(), guard)
	})
	return domain.CloneObjectInfo(info), err
}
func (r *memoryObjects) Delete(ctx context.Context, warehouse, key string) error {
	return r.store.Update(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(true); err != nil {
			return err
		}
		objects := maps.Clone(s.objects[warehouse])
		delete(objects, key)
		if len(objects) == 0 {
			delete(s.objects, warehouse)
		} else {
			s.objects[warehouse] = objects
		}
		return nil
	})
}
func (r *memoryObjects) List(ctx context.Context, warehouse, prefix string) ([]domain.ObjectInfo, error) {
	objects := []domain.ObjectInfo{}
	err := r.store.View(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(false); err != nil {
			return err
		}
		for key, object := range s.objects[warehouse] {
			if strings.HasPrefix(key, prefix) {
				objects = append(objects, domain.CloneObjectInfo(object.info))
			}
		}
		return nil
	})
	slices.SortFunc(objects, func(a, b domain.ObjectInfo) int { return strings.Compare(a.Key, b.Key) })
	return objects, err
}
func (r *memoryObjects) CreateMultipart(ctx context.Context, upload domain.MultipartUpload, guard domain.PublicationGuard) error {
	upload.Attributes = domain.CloneObjectAttributes(upload.Attributes)
	return r.store.Update(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(true); err != nil {
			return err
		}
		key := uploadKey{upload.Warehouse, upload.Key, upload.ID}
		if _, exists := s.uploads[key]; exists {
			return domain.NoSuchMultipartUpload()
		}
		s.uploads[key] = warehouseUpload{info: upload, parts: make(map[int]warehousePart)}
		return publicationGuard(tx.Context(), guard)
	})
}
func (r *memoryObjects) UploadMultipartPart(ctx context.Context, warehouse, key, id string, part domain.MultipartPart, data []byte, guard domain.PublicationGuard) error {
	return r.store.Update(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(true); err != nil {
			return err
		}
		uKey := uploadKey{warehouse, key, id}
		upload, exists := s.uploads[uKey]
		if !exists {
			return domain.NoSuchMultipartUpload()
		}
		encrypted, err := s3tablescrypt.Seal(data, s3tablescrypt.PartIdentity(warehouse, key, id, int64(part.Number)))
		if err != nil {
			return err
		}
		upload.parts = maps.Clone(upload.parts)
		upload.parts[part.Number] = warehousePart{info: part, data: encrypted}
		s.uploads[uKey] = upload
		return publicationGuard(tx.Context(), guard)
	})
}
func (r *memoryObjects) ListMultipartParts(ctx context.Context, warehouse, key, id string) (domain.MultipartUpload, []domain.MultipartPart, error) {
	var upload domain.MultipartUpload
	parts := []domain.MultipartPart{}
	err := r.store.View(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(false); err != nil {
			return err
		}
		stored, exists := s.uploads[uploadKey{warehouse, key, id}]
		if !exists {
			return domain.NoSuchMultipartUpload()
		}
		upload = stored.info
		upload.Attributes = domain.CloneObjectAttributes(upload.Attributes)
		for _, part := range stored.parts {
			parts = append(parts, part.info)
		}
		return nil
	})
	slices.SortFunc(parts, func(a, b domain.MultipartPart) int { return a.Number - b.Number })
	return upload, parts, err
}
func (r *memoryObjects) CompleteMultipart(ctx context.Context, warehouse, key, id string, selected []domain.CompletedPart, modified time.Time, conditions domain.ObjectConditions, checksums domain.ObjectChecksums, guard domain.PublicationGuard) (domain.ObjectInfo, error) {
	var info domain.ObjectInfo
	err := r.store.Update(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(true); err != nil {
			return err
		}
		uKey := uploadKey{warehouse, key, id}
		upload, exists := s.uploads[uKey]
		if !exists {
			return domain.NoSuchMultipartUpload()
		}
		if err := domain.ValidateMultipartCompletionParts(selected); err != nil {
			return err
		}
		var total int64
		for _, selection := range selected {
			if part, exists := upload.parts[selection.Number]; exists {
				if part.info.Size < 0 || part.info.Size > domain.MultipartMaximumPartSize || part.info.Size > int64(int(^uint(0)>>1))-total {
					return s3tablescrypt.ErrEnvelope
				}
				total += part.info.Size
			}
		}
		data := make([]byte, 0, int(total))
		parts := make(map[int]domain.StoredMultipartPart, len(selected))
		for _, selection := range selected {
			part, ok := upload.parts[selection.Number]
			if !ok {
				continue
			}
			start := len(data)
			var err error
			data, err = part.data.Open(data, s3tablescrypt.PartIdentity(warehouse, key, id, int64(selection.Number)), part.info.Size)
			if err != nil {
				return err
			}
			parts[selection.Number] = domain.StoredMultipartPart{MultipartPart: part.info, Data: data[start:]}
		}
		assembled, err := domain.MultipartObjectInfo(upload.info, parts, selected, modified, checksums)
		if err != nil {
			return err
		}
		if err := domain.CheckMultipartCompletionConditions(assembled, conditions); err != nil {
			return err
		}
		_, exists = s.objects[warehouse][key]
		// Keep checksum validation ahead of existence, without masking revocation.
		if err := publicationGuard(tx.Context(), guard); err != nil {
			return err
		}
		if err := domain.CheckObjectConditions(exists, conditions); err != nil {
			return err
		}
		info = assembled
		encrypted, err := s3tablescrypt.Seal(data, s3tablescrypt.ObjectIdentity(warehouse, key))
		if err != nil {
			return err
		}
		putMemoryObject(s, warehouse, warehouseObject{info: info, data: encrypted})
		delete(s.uploads, uKey)
		return publicationGuard(tx.Context(), guard)
	})
	return domain.CloneObjectInfo(info), err
}
func (r *memoryObjects) AbortMultipart(ctx context.Context, warehouse, key, id string, guard domain.PublicationGuard) error {
	return r.store.Update(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(true); err != nil {
			return err
		}
		uKey := uploadKey{warehouse, key, id}
		if _, exists := s.uploads[uKey]; !exists {
			return domain.NoSuchMultipartUpload()
		}
		delete(s.uploads, uKey)
		return publicationGuard(tx.Context(), guard)
	})
}
func (r *memoryObjects) PurgeWarehouse(ctx context.Context, warehouse string) error {
	return r.store.Update(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(true); err != nil {
			return err
		}
		delete(s.objects, warehouse)
		for key := range s.uploads {
			if key.warehouse == warehouse {
				delete(s.uploads, key)
			}
		}
		return nil
	})
}

func (r *memoryObjects) GetMultipartUpload(ctx context.Context, warehouse, key, id string) (domain.MultipartUpload, error) {
	var upload domain.MultipartUpload
	err := r.store.View(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(false); err != nil {
			return err
		}
		stored, exists := s.uploads[uploadKey{warehouse, key, id}]
		if !exists {
			return domain.NoSuchMultipartUpload()
		}
		upload = stored.info
		upload.Attributes = domain.CloneObjectAttributes(upload.Attributes)
		return nil
	})
	return upload, err
}
