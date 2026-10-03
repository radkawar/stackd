package s3

import (
	"cmp"
	"slices"

	"stackd/storage/memory"
)

func cloneAnalyticsConfiguration(config AnalyticsConfiguration) AnalyticsConfiguration {
	if config.Filter != nil {
		config.Filter = new(cloneObjectFilter(*config.Filter))
	}
	if config.Destination != nil {
		destination := *config.Destination
		destination.AccountID = copyOptional(destination.AccountID)
		destination.Prefix = copyOptional(destination.Prefix)
		config.Destination = &destination
	}
	return config
}

func (r memoryReader) BucketAnalyticsConfiguration(key BucketKey, id string) (*AnalyticsConfiguration, error) {
	var out *AnalyticsConfiguration
	err := r.repository.analytics.View(r.Context(), func(state *map[BucketKey]map[string]AnalyticsConfiguration, _ *memory.Transaction) error {
		if config, ok := (*state)[key][id]; ok {
			out = new(cloneAnalyticsConfiguration(config))
		}
		return nil
	})
	return out, err
}

func (r memoryReader) BucketAnalyticsConfigurations(query BucketConfigurationQuery) ([]AnalyticsConfiguration, error) {
	out := []AnalyticsConfiguration{}
	err := r.repository.analytics.View(r.Context(), func(state *map[BucketKey]map[string]AnalyticsConfiguration, _ *memory.Transaction) error {
		if query.Limit <= 0 {
			return nil
		}
		for id, config := range (*state)[query.Bucket] {
			if id > query.After {
				out = append(out, config)
			}
		}
		slices.SortFunc(out, func(a, b AnalyticsConfiguration) int { return cmp.Compare(a.ID, b.ID) })
		if len(out) > query.Limit {
			out = out[:query.Limit:query.Limit]
		}
		for i := range out {
			out[i] = cloneAnalyticsConfiguration(out[i])
		}
		return nil
	})
	return out, err
}

func (r memoryReader) BucketAnalyticsConfigurationCount(key BucketKey) (int, error) {
	var count int
	err := r.repository.analytics.View(r.Context(), func(state *map[BucketKey]map[string]AnalyticsConfiguration, _ *memory.Transaction) error {
		count = len((*state)[key])
		return nil
	})
	return count, err
}

func (w memoryWriter) PutBucketAnalyticsConfiguration(key BucketKey, config AnalyticsConfiguration) error {
	return w.repository.analytics.Update(w.Context(), func(state *map[BucketKey]map[string]AnalyticsConfiguration, _ *memory.Transaction) error {
		if (*state)[key] == nil {
			(*state)[key] = map[string]AnalyticsConfiguration{}
		}
		(*state)[key][config.ID] = cloneAnalyticsConfiguration(config)
		return nil
	})
}

func (w memoryWriter) DeleteBucketAnalyticsConfiguration(key BucketKey, id string) error {
	return w.repository.analytics.Update(w.Context(), func(state *map[BucketKey]map[string]AnalyticsConfiguration, _ *memory.Transaction) error {
		delete((*state)[key], id)
		if len((*state)[key]) == 0 {
			delete(*state, key)
		}
		return nil
	})
}

func (w memoryWriter) deleteBucketAnalytics(key BucketKey) error {
	return w.repository.analytics.Update(w.Context(), func(state *map[BucketKey]map[string]AnalyticsConfiguration, _ *memory.Transaction) error {
		delete(*state, key)
		return nil
	})
}
