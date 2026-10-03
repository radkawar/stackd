package s3

import (
	"cmp"

	"stackd/storage/memory"
)

func (r memoryReader) ObjectRestore(key ObjectVersionKey) (*ObjectRestore, error) {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	var out *ObjectRestore
	err := r.repository.objectRestores.View(r.Context(), func(state *map[ObjectVersionKey]ObjectRestore, _ *memory.Transaction) error {
		if value, ok := (*state)[key]; ok {
			out = &value
		}
		return nil
	})
	return out, err
}

func (r memoryReader) NextObjectRestore() (*ObjectRestore, error) {
	var out ObjectRestore
	found := false
	err := r.repository.objectRestores.View(r.Context(), func(state *map[ObjectVersionKey]ObjectRestore, _ *memory.Transaction) error {
		for key, value := range *state {
			if !found || value.Due.Before(out.Due) || (value.Due.Equal(out.Due) && cmp.Or(
				cmp.Compare(key.Bucket.Partition, out.Key.Bucket.Partition),
				cmp.Compare(key.Bucket.Name, out.Key.Bucket.Name),
				cmp.Compare(key.Name, out.Key.Name),
				cmp.Compare(key.VersionID, out.Key.VersionID),
			) < 0) {
				out = value
				found = true
			}
		}
		return nil
	})
	if err != nil || !found {
		return nil, err
	}
	return &out, nil
}

func (w memoryWriter) PutObjectRestore(value ObjectRestore) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if value.Key.VersionID == "" {
		value.Key.VersionID = "null"
	}
	return w.repository.objects.View(w.Context(), func(objects *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		if _, ok := (*objects)[value.Key]; !ok {
			return ErrNotFound
		}
		return w.repository.objectRestores.Update(w.Context(), func(state *map[ObjectVersionKey]ObjectRestore, _ *memory.Transaction) error {
			(*state)[value.Key] = value
			return nil
		})
	})
}

func (w memoryWriter) DeleteObjectRestore(key ObjectVersionKey) error {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	return w.repository.objectRestores.Update(w.Context(), func(state *map[ObjectVersionKey]ObjectRestore, _ *memory.Transaction) error {
		delete(*state, key)
		return nil
	})
}
