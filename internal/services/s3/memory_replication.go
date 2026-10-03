package s3

import (
	"slices"

	"stackd/storage/memory"
)

func cloneReplication(config *ReplicationConfiguration) *ReplicationConfiguration {
	if config == nil {
		return nil
	}
	out := *config
	out.Rules = slices.Clone(config.Rules)
	for i := range out.Rules {
		rule := &out.Rules[i]
		rule.Priority = copyOptional(rule.Priority)
		rule.Filter.Prefix = copyOptional(rule.Filter.Prefix)
		rule.Filter.Tags = slices.Clone(rule.Filter.Tags)
		rule.Destination = cloneReplicationDestination(rule.Destination)
	}
	return &out
}

func cloneReplicationDestination(destination ReplicationDestination) ReplicationDestination {
	destination.MetricsMinutes = copyOptional(destination.MetricsMinutes)
	destination.TimeMinutes = copyOptional(destination.TimeMinutes)
	return destination
}

func (r memoryReader) BucketReplication(key BucketKey) (*ReplicationConfiguration, error) {
	var out *ReplicationConfiguration
	err := r.repository.replication.View(r.Context(), func(state *map[BucketKey]ReplicationConfiguration, _ *memory.Transaction) error {
		if config, ok := (*state)[key]; ok {
			out = cloneReplication(&config)
		}
		return nil
	})
	return out, err
}

func (w memoryWriter) ReplaceBucketReplication(key BucketKey, config *ReplicationConfiguration) error {
	return w.repository.replication.Update(w.Context(), func(state *map[BucketKey]ReplicationConfiguration, _ *memory.Transaction) error {
		if config == nil {
			delete(*state, key)
		} else {
			(*state)[key] = *cloneReplication(config)
		}
		return nil
	})
}
