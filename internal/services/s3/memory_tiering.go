package s3

import (
	"cmp"
	"slices"
	"time"

	"stackd/storage/memory"
)

type memoryTieringKey struct {
	Bucket BucketKey
	ID     string
}

func cloneTieringConfiguration(config TieringConfiguration) TieringConfiguration {
	if config.Filter != nil {
		config.Filter = new(cloneObjectFilter(*config.Filter))
	}
	config.Tierings = slices.Clone(config.Tierings)
	return config
}

func (r memoryReader) BucketTieringConfiguration(key BucketKey, id string) (*TieringConfiguration, error) {
	var out *TieringConfiguration
	err := r.repository.tiering.View(r.Context(), func(state *map[memoryTieringKey]TieringConfiguration, _ *memory.Transaction) error {
		if config, ok := (*state)[memoryTieringKey{Bucket: key, ID: id}]; ok {
			out = new(cloneTieringConfiguration(config))
		}
		return nil
	})
	return out, err
}

func (r memoryReader) BucketTieringConfigurations(query BucketConfigurationQuery) ([]TieringConfiguration, error) {
	out := []TieringConfiguration{}
	err := r.repository.tiering.View(r.Context(), func(state *map[memoryTieringKey]TieringConfiguration, _ *memory.Transaction) error {
		if query.Limit <= 0 {
			return nil
		}
		for key, config := range *state {
			if key.Bucket == query.Bucket && key.ID > query.After {
				out = append(out, config)
			}
		}
		slices.SortFunc(out, func(a, b TieringConfiguration) int { return cmp.Compare(a.ID, b.ID) })
		if len(out) > query.Limit {
			out = out[:query.Limit]
		}
		for i := range out {
			out[i] = cloneTieringConfiguration(out[i])
		}
		return nil
	})
	return out, err
}

func (r memoryReader) BucketTieringConfigurationCount(key BucketKey) (int, error) {
	var count int
	err := r.repository.tiering.View(r.Context(), func(state *map[memoryTieringKey]TieringConfiguration, _ *memory.Transaction) error {
		for configKey := range *state {
			if configKey.Bucket == key {
				count++
			}
		}
		return nil
	})
	return count, err
}

func (r memoryReader) NextTieringScan() (*BucketScan, error) {
	var out *BucketScan
	err := r.repository.tieringScans.View(r.Context(), func(state *map[BucketKey]time.Time, _ *memory.Transaction) error {
		for key, due := range *state {
			if out == nil || due.Before(out.Due) || due.Equal(out.Due) && (key.Partition < out.Bucket.Partition || key.Partition == out.Bucket.Partition && key.Name < out.Bucket.Name) {
				out = &BucketScan{Bucket: key, Due: due}
			}
		}
		return nil
	})
	return out, err
}

func (r memoryReader) BucketHasEnabledTiering(key BucketKey) (bool, error) {
	var enabled bool
	err := r.repository.tiering.View(r.Context(), func(state *map[memoryTieringKey]TieringConfiguration, _ *memory.Transaction) error {
		for configKey, config := range *state {
			if configKey.Bucket == key && config.Enabled {
				enabled = true
				break
			}
		}
		return nil
	})
	return enabled, err
}

func (w memoryWriter) PutBucketTieringConfiguration(key BucketKey, config TieringConfiguration) error {
	return w.repository.tiering.Update(w.Context(), func(state *map[memoryTieringKey]TieringConfiguration, _ *memory.Transaction) error {
		(*state)[memoryTieringKey{Bucket: key, ID: config.ID}] = cloneTieringConfiguration(config)
		return nil
	})
}

func (w memoryWriter) DeleteBucketTieringConfiguration(key BucketKey, id string) error {
	return w.repository.tiering.Update(w.Context(), func(state *map[memoryTieringKey]TieringConfiguration, _ *memory.Transaction) error {
		delete(*state, memoryTieringKey{Bucket: key, ID: id})
		return nil
	})
}

func (w memoryWriter) SetTieringScan(key BucketKey, due *time.Time) error {
	return w.repository.tieringScans.Update(w.Context(), func(state *map[BucketKey]time.Time, _ *memory.Transaction) error {
		if due == nil {
			delete(*state, key)
		} else {
			(*state)[key] = due.UTC()
		}
		return nil
	})
}

func (w memoryWriter) SetObjectTiering(key ObjectVersionKey, createdOrder int64, tiering *ObjectTiering) error {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	return w.repository.objects.Update(w.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		object, ok := (*state)[key]
		if !ok || object.CreatedOrder != createdOrder || tiering != nil && object.StorageClass != "INTELLIGENT_TIERING" {
			return nil
		}
		object.Tiering = copyOptional(tiering)
		(*state)[key] = object
		return nil
	})
}

func (w memoryWriter) deleteBucketTiering(key BucketKey) error {
	if err := w.repository.tiering.Update(w.Context(), func(state *map[memoryTieringKey]TieringConfiguration, _ *memory.Transaction) error {
		for configKey := range *state {
			if configKey.Bucket == key {
				delete(*state, configKey)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return w.SetTieringScan(key, nil)
}
