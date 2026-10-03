package s3

import (
	"slices"

	"stackd/storage/memory"
)

func cloneLogging(config *LoggingConfiguration) *LoggingConfiguration {
	if config == nil {
		return nil
	}
	out := *config
	out.Grants = slices.Clone(config.Grants)
	return &out
}

func (r memoryReader) BucketLogging(key BucketKey) (*LoggingConfiguration, error) {
	var out *LoggingConfiguration
	err := r.repository.logging.View(r.Context(), func(state *map[BucketKey]LoggingConfiguration, _ *memory.Transaction) error {
		if config, ok := (*state)[key]; ok {
			out = cloneLogging(&config)
		}
		return nil
	})
	return out, err
}

func (w memoryWriter) ReplaceBucketLogging(key BucketKey, config *LoggingConfiguration) error {
	return w.repository.logging.Update(w.Context(), func(state *map[BucketKey]LoggingConfiguration, _ *memory.Transaction) error {
		if config == nil {
			delete(*state, key)
		} else {
			(*state)[key] = *cloneLogging(config)
		}
		return nil
	})
}
