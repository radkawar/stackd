package s3

import (
	"cmp"
	"slices"
	"strings"

	"stackd/storage/memory"
)

// Ciphertext is immutable after ingress. Completion transfers its references
// from pending ownership to the published version; only public reads copy it.
type memoryMultipartPart struct {
	metadata   PartRecord
	ciphertext []byte
}

func cloneMultipartUpload(v MultipartUploadRecord, includeKey bool) MultipartUploadRecord {
	v.ObjectRecord = cloneObject(v.ObjectRecord, includeKey)
	v.Tags = slices.Clone(v.Tags)
	return v
}

func (r memoryReader) MultipartUpload(key MultipartUploadKey) (MultipartUploadRecord, error) {
	var out MultipartUploadRecord
	err := r.repository.uploads.View(r.Context(), func(state *map[MultipartUploadKey]MultipartUploadRecord, _ *memory.Transaction) error {
		v, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		out = cloneMultipartUpload(v, true)
		return nil
	})
	return out, err
}

func (r memoryReader) MultipartUploads(query MultipartQuery) ([]MultipartUploadRecord, error) {
	out := []MultipartUploadRecord{}
	err := r.repository.uploads.View(r.Context(), func(state *map[MultipartUploadKey]MultipartUploadRecord, _ *memory.Transaction) error {
		if query.Limit <= 0 {
			return nil
		}
		for key, v := range *state {
			if key.Bucket != query.Bucket || !strings.HasPrefix(key.Name, query.Prefix) {
				continue
			}
			if key.Name > query.AfterKey || (key.Name == query.AfterKey && query.AfterOrder != nil && v.CreatedOrder > *query.AfterOrder) {
				out = append(out, v)
			}
		}
		slices.SortFunc(out, func(a, b MultipartUploadRecord) int {
			if n := cmp.Compare(a.Key.Name, b.Key.Name); n != 0 {
				return n
			}
			return cmp.Compare(a.CreatedOrder, b.CreatedOrder)
		})
		if len(out) > query.Limit {
			out = out[:query.Limit]
		}
		for i := range out {
			out[i] = cloneMultipartUpload(out[i], false)
		}
		return nil
	})
	return out, err
}

func (r memoryReader) MultipartParts(key MultipartUploadKey, after int32, limit int) ([]PartRecord, error) {
	out := []PartRecord{}
	err := r.repository.uploads.View(r.Context(), func(state *map[MultipartUploadKey]MultipartUploadRecord, _ *memory.Transaction) error {
		if _, ok := (*state)[key]; !ok {
			return ErrNotFound
		}
		if limit <= 0 {
			return nil
		}
		return r.repository.uploadParts.View(r.Context(), func(parts *map[MultipartUploadKey]map[int32]memoryMultipartPart, _ *memory.Transaction) error {
			for number, part := range (*parts)[key] {
				if number > after {
					out = append(out, part.metadata)
				}
			}
			slices.SortFunc(out, func(a, b PartRecord) int { return cmp.Compare(a.Number, b.Number) })
			if len(out) > limit {
				out = out[:limit]
			}
			return nil
		})
	})
	return out, err
}

func (r memoryReader) ObjectParts(key ObjectVersionKey) ([]PartRecord, error) {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	out := []PartRecord{}
	err := r.repository.objects.View(r.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		if _, ok := (*state)[key]; !ok {
			return ErrNotFound
		}
		return r.repository.objectParts.View(r.Context(), func(parts *map[ObjectVersionKey][]PartRecord, _ *memory.Transaction) error {
			out = append(out, (*parts)[key]...)
			return nil
		})
	})
	return out, err
}

func (r memoryReader) CompletedMultipartUpload(key MultipartUploadKey) (ObjectRecord, error) {
	var out ObjectRecord
	err := r.repository.objects.View(r.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		for version, v := range *state {
			if version.ObjectKey == key.ObjectKey && v.UploadID != "" && v.UploadID == key.UploadID {
				out = cloneObject(v, true)
				return nil
			}
		}
		return ErrNotFound
	})
	return out, err
}

func (w memoryWriter) PutMultipartUpload(v *MultipartUploadRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	bucket, ok := (*w.state)[v.Key.Bucket]
	if !ok {
		return ErrNotFound
	}
	if v.ACL == nil {
		v.ACL = DefaultACL(v.Key.Bucket.Partition, bucket.AccountID)
	}
	return w.repository.uploads.Update(w.Context(), func(state *map[MultipartUploadKey]MultipartUploadRecord, _ *memory.Transaction) error {
		order, err := w.nextObjectSequence()
		if err != nil {
			return err
		}
		if err := v.AssignInitiation(order); err != nil {
			return err
		}
		(*state)[v.UploadKey()] = cloneMultipartUpload(*v, true)
		return nil
	})
}

func (w memoryWriter) PutMultipartPart(key MultipartUploadKey, part PartRecord, data []byte) error {
	return w.repository.uploadParts.Update(w.Context(), func(state *map[MultipartUploadKey]map[int32]memoryMultipartPart, _ *memory.Transaction) error {
		if err := w.repository.uploads.View(w.Context(), func(uploads *map[MultipartUploadKey]MultipartUploadRecord, _ *memory.Transaction) error {
			if _, ok := (*uploads)[key]; !ok {
				return ErrNotFound
			}
			return nil
		}); err != nil {
			return err
		}
		parts := (*state)[key]
		if parts == nil {
			parts = map[int32]memoryMultipartPart{}
			(*state)[key] = parts
		}
		parts[part.Number] = memoryMultipartPart{metadata: part, ciphertext: slices.Clone(data)}
		return nil
	})
}

func (w memoryWriter) DeleteMultipartUpload(key MultipartUploadKey) error {
	if err := w.repository.uploads.Update(w.Context(), func(state *map[MultipartUploadKey]MultipartUploadRecord, _ *memory.Transaction) error {
		delete(*state, key)
		return nil
	}); err != nil {
		return err
	}
	return w.repository.uploadParts.Update(w.Context(), func(state *map[MultipartUploadKey]map[int32]memoryMultipartPart, _ *memory.Transaction) error {
		delete(*state, key)
		return nil
	})
}

func (w memoryWriter) CompleteMultipartUpload(key MultipartUploadKey, object ObjectRecord, selectedNumbers []int32, retain bool) (int64, error) {
	var sequence int64
	err := w.repository.uploads.Update(w.Context(), func(uploads *map[MultipartUploadKey]MultipartUploadRecord, _ *memory.Transaction) error {
		upload, ok := (*uploads)[key]
		if !ok {
			return ErrNotFound
		}
		return w.repository.uploadParts.Update(w.Context(), func(pending *map[MultipartUploadKey]map[int32]memoryMultipartPart, _ *memory.Transaction) error {
			if retain {
				parts := make([]PartRecord, len(selectedNumbers))
				data := make([][]byte, len(selectedNumbers))
				for i, number := range selectedNumbers {
					part, ok := (*pending)[key][number]
					if !ok {
						return ErrNotFound
					}
					parts[i], data[i] = part.metadata, part.ciphertext
				}
				object.Key = key.ObjectKey
				object.UploadID = key.UploadID
				object.CreatedOrder = upload.CreatedOrder
				object.Modified = upload.Modified
				object.StorageClass = upload.StorageClass
				object.ACL = upload.ACL
				if err := w.putObjectRecord(&object); err != nil {
					return err
				}
				version := object.VersionKey()
				if err := w.ReplaceObjectTags(version, upload.Tags); err != nil {
					return err
				}
				if err := w.repository.objectParts.Update(w.Context(), func(state *map[ObjectVersionKey][]PartRecord, _ *memory.Transaction) error {
					(*state)[version] = parts
					return nil
				}); err != nil {
					return err
				}
				if err := w.repository.data.Update(w.Context(), func(state *map[ObjectVersionKey][][]byte, _ *memory.Transaction) error {
					(*state)[version] = data
					return nil
				}); err != nil {
					return err
				}
				sequence = object.Sequence
			} else {
				var err error
				sequence, err = w.nextObjectSequence()
				if err != nil {
					return err
				}
			}
			delete(*pending, key)
			delete(*uploads, key)
			return nil
		})
	})
	return sequence, err
}

// A zero cutoff represents a deletion of the current key, superseding every
// active upload; writes supersede only uploads initiated before their version.
func (w memoryWriter) supersedeMultipartUploads(key ObjectKey, before int64) error {
	return w.repository.uploads.Update(w.Context(), func(state *map[MultipartUploadKey]MultipartUploadRecord, _ *memory.Transaction) error {
		for uploadKey, upload := range *state {
			if uploadKey.ObjectKey == key && (before == 0 || upload.CreatedOrder < before) {
				upload.Superseded = true
				(*state)[uploadKey] = upload
			}
		}
		return nil
	})
}
