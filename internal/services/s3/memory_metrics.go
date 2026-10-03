package s3

import (
	"cmp"
	"slices"

	"stackd/storage/memory"
)

func cloneMetricsConfiguration(config RequestMetricsConfiguration) RequestMetricsConfiguration {
	if config.Filter != nil {
		filter := *config.Filter
		filter.ObjectFilter = cloneObjectFilter(filter.ObjectFilter)
		config.Filter = &filter
	}
	return config
}

func (r memoryReader) BucketMetricsConfiguration(key BucketKey, id string) (*RequestMetricsConfiguration, error) {
	var out *RequestMetricsConfiguration
	err := r.repository.requestMetrics.View(r.Context(), func(state *map[BucketKey]map[string]RequestMetricsConfiguration, _ *memory.Transaction) error {
		if config, ok := (*state)[key][id]; ok {
			out = new(cloneMetricsConfiguration(config))
		}
		return nil
	})
	return out, err
}

func (r memoryReader) BucketMetricsConfigurations(query BucketConfigurationQuery) ([]RequestMetricsConfiguration, error) {
	out := []RequestMetricsConfiguration{}
	err := r.repository.requestMetrics.View(r.Context(), func(state *map[BucketKey]map[string]RequestMetricsConfiguration, _ *memory.Transaction) error {
		if query.Limit <= 0 {
			return nil
		}
		for id, config := range (*state)[query.Bucket] {
			if id > query.After {
				out = append(out, config)
			}
		}
		slices.SortFunc(out, func(a, b RequestMetricsConfiguration) int { return cmp.Compare(a.ID, b.ID) })
		if len(out) > query.Limit {
			out = out[:query.Limit]
		}
		for i := range out {
			out[i] = cloneMetricsConfiguration(out[i])
		}
		return nil
	})
	return out, err
}

func (r memoryReader) BucketMetricsConfigurationCount(key BucketKey) (int, error) {
	var count int
	err := r.repository.requestMetrics.View(r.Context(), func(state *map[BucketKey]map[string]RequestMetricsConfiguration, _ *memory.Transaction) error {
		count = len((*state)[key])
		return nil
	})
	return count, err
}

func (w memoryWriter) PutBucketMetricsConfiguration(key BucketKey, config RequestMetricsConfiguration) error {
	return w.repository.requestMetrics.Update(w.Context(), func(state *map[BucketKey]map[string]RequestMetricsConfiguration, _ *memory.Transaction) error {
		if (*state)[key] == nil {
			(*state)[key] = map[string]RequestMetricsConfiguration{}
		}
		(*state)[key][config.ID] = cloneMetricsConfiguration(config)
		return nil
	})
}

func (w memoryWriter) DeleteBucketMetricsConfiguration(key BucketKey, id string) error {
	return w.repository.requestMetrics.Update(w.Context(), func(state *map[BucketKey]map[string]RequestMetricsConfiguration, _ *memory.Transaction) error {
		delete((*state)[key], id)
		if len((*state)[key]) == 0 {
			delete(*state, key)
		}
		return nil
	})
}

func (w memoryWriter) deleteBucketMetrics(key BucketKey) error {
	return w.repository.requestMetrics.Update(w.Context(), func(state *map[BucketKey]map[string]RequestMetricsConfiguration, _ *memory.Transaction) error {
		delete(*state, key)
		return nil
	})
}
