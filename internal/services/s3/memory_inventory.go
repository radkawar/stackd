package s3

import (
	"cmp"
	"slices"
	"time"

	"stackd/storage/memory"
)

func cloneInventoryConfiguration(config InventoryConfiguration) InventoryConfiguration {
	config.FilterPrefix = copyOptional(config.FilterPrefix)
	config.OptionalFields = slices.Clone(config.OptionalFields)
	config.Destination.AccountID = copyOptional(config.Destination.AccountID)
	config.Destination.Prefix = copyOptional(config.Destination.Prefix)
	return config
}

func (r memoryReader) BucketInventoryConfiguration(key BucketKey, id string) (*InventoryConfiguration, error) {
	var out *InventoryConfiguration
	err := r.repository.inventory.View(r.Context(), func(state *map[BucketKey]map[string]InventoryConfiguration, _ *memory.Transaction) error {
		if config, ok := (*state)[key][id]; ok {
			out = new(cloneInventoryConfiguration(config))
		}
		return nil
	})
	return out, err
}

func (r memoryReader) BucketInventoryConfigurations(query BucketConfigurationQuery) ([]InventoryConfiguration, error) {
	out := []InventoryConfiguration{}
	err := r.repository.inventory.View(r.Context(), func(state *map[BucketKey]map[string]InventoryConfiguration, _ *memory.Transaction) error {
		if query.Limit <= 0 {
			return nil
		}
		for id, config := range (*state)[query.Bucket] {
			if id > query.After {
				out = append(out, config)
			}
		}
		slices.SortFunc(out, func(a, b InventoryConfiguration) int { return cmp.Compare(a.ID, b.ID) })
		if len(out) > query.Limit {
			out = out[:query.Limit:query.Limit]
		}
		for i := range out {
			out[i] = cloneInventoryConfiguration(out[i])
		}
		return nil
	})
	return out, err
}

func (r memoryReader) BucketInventoryConfigurationCount(key BucketKey) (int, error) {
	var count int
	err := r.repository.inventory.View(r.Context(), func(state *map[BucketKey]map[string]InventoryConfiguration, _ *memory.Transaction) error {
		count = len((*state)[key])
		return nil
	})
	return count, err
}

func (r memoryReader) NextInventoryConfiguration() (BucketKey, *InventoryConfiguration, error) {
	var key BucketKey
	var selected InventoryConfiguration
	var found bool
	err := r.repository.inventory.View(r.Context(), func(state *map[BucketKey]map[string]InventoryConfiguration, _ *memory.Transaction) error {
		for bucket, configurations := range *state {
			for _, config := range configurations {
				if !config.Enabled {
					continue
				}
				if !found || config.NextReport.Before(selected.NextReport) || config.NextReport.Equal(selected.NextReport) && cmp.Or(
					cmp.Compare(bucket.Partition, key.Partition),
					cmp.Compare(bucket.Name, key.Name),
					cmp.Compare(config.ID, selected.ID),
				) < 0 {
					key, selected, found = bucket, config, true
				}
			}
		}
		return nil
	})
	if err != nil || !found {
		return BucketKey{}, nil, err
	}
	return key, new(cloneInventoryConfiguration(selected)), nil
}

func (w memoryWriter) PutBucketInventoryConfiguration(key BucketKey, config InventoryConfiguration) error {
	return w.repository.inventory.Update(w.Context(), func(state *map[BucketKey]map[string]InventoryConfiguration, _ *memory.Transaction) error {
		if (*state)[key] == nil {
			(*state)[key] = map[string]InventoryConfiguration{}
		}
		config.NextReport = config.NextReport.UTC()
		(*state)[key][config.ID] = cloneInventoryConfiguration(config)
		return nil
	})
}

func (w memoryWriter) DeleteBucketInventoryConfiguration(key BucketKey, id string) error {
	return w.repository.inventory.Update(w.Context(), func(state *map[BucketKey]map[string]InventoryConfiguration, _ *memory.Transaction) error {
		delete((*state)[key], id)
		if len((*state)[key]) == 0 {
			delete(*state, key)
		}
		return nil
	})
}

func (w memoryWriter) AdvanceInventoryReport(key BucketKey, id, parentEventID string, previous, next time.Time) error {
	return w.repository.inventory.Update(w.Context(), func(state *map[BucketKey]map[string]InventoryConfiguration, _ *memory.Transaction) error {
		config, ok := (*state)[key][id]
		if !ok || !config.Enabled || config.ParentEventID != parentEventID || !config.NextReport.Equal(previous) {
			return nil
		}
		config.NextReport = next.UTC()
		(*state)[key][id] = config
		return nil
	})
}

func (w memoryWriter) deleteBucketInventory(key BucketKey) error {
	return w.repository.inventory.Update(w.Context(), func(state *map[BucketKey]map[string]InventoryConfiguration, _ *memory.Transaction) error {
		delete(*state, key)
		return nil
	})
}
