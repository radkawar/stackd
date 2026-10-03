package s3

import (
	"slices"
	"time"

	"stackd/storage/memory"
)

func cloneLifecycle(config *LifecycleConfiguration) *LifecycleConfiguration {
	if config == nil {
		return nil
	}
	out := *config
	out.Rules = slices.Clone(config.Rules)
	out.NextScan = copyOptional(config.NextScan)
	for i := range out.Rules {
		rule := &out.Rules[i]
		rule.Filter = cloneObjectFilter(rule.Filter)
		rule.Expiration = copyOptional(rule.Expiration)
		if rule.Expiration != nil {
			rule.Expiration.LifecycleWhen = cloneLifecycleWhen(rule.Expiration.LifecycleWhen)
			rule.Expiration.ExpiredObjectDeleteMarker = copyOptional(rule.Expiration.ExpiredObjectDeleteMarker)
		}
		rule.Transitions = slices.Clone(rule.Transitions)
		for j := range rule.Transitions {
			rule.Transitions[j].LifecycleWhen = cloneLifecycleWhen(rule.Transitions[j].LifecycleWhen)
		}
		rule.NoncurrentExpiration = copyOptional(rule.NoncurrentExpiration)
		if rule.NoncurrentExpiration != nil {
			rule.NoncurrentExpiration.NewerNoncurrentVersions = copyOptional(rule.NoncurrentExpiration.NewerNoncurrentVersions)
		}
		rule.NoncurrentTransitions = slices.Clone(rule.NoncurrentTransitions)
		for j := range rule.NoncurrentTransitions {
			rule.NoncurrentTransitions[j].NewerNoncurrentVersions = copyOptional(rule.NoncurrentTransitions[j].NewerNoncurrentVersions)
		}
		rule.AbortIncompleteDays = copyOptional(rule.AbortIncompleteDays)
	}
	return &out
}

func cloneLifecycleWhen(when LifecycleWhen) LifecycleWhen {
	when.Date, when.Days = copyOptional(when.Date), copyOptional(when.Days)
	return when
}

func (r memoryReader) BucketLifecycle(key BucketKey) (*LifecycleConfiguration, error) {
	var out *LifecycleConfiguration
	err := r.repository.lifecycle.View(r.Context(), func(state *map[BucketKey]LifecycleConfiguration, _ *memory.Transaction) error {
		if config, ok := (*state)[key]; ok {
			out = cloneLifecycle(&config)
		}
		return nil
	})
	return out, err
}

func (r memoryReader) NextLifecycleScan() (*BucketScan, error) {
	var out *BucketScan
	err := r.repository.lifecycle.View(r.Context(), func(state *map[BucketKey]LifecycleConfiguration, _ *memory.Transaction) error {
		for bucket, config := range *state {
			if config.NextScan == nil {
				continue
			}
			if out == nil || config.NextScan.Before(out.Due) || config.NextScan.Equal(out.Due) && (bucket.Partition < out.Bucket.Partition || bucket.Partition == out.Bucket.Partition && bucket.Name < out.Bucket.Name) {
				out = &BucketScan{Bucket: bucket, Due: *config.NextScan}
			}
		}
		return nil
	})
	return out, err
}

func (w memoryWriter) ReplaceBucketLifecycle(key BucketKey, config *LifecycleConfiguration) error {
	return w.repository.lifecycle.Update(w.Context(), func(state *map[BucketKey]LifecycleConfiguration, _ *memory.Transaction) error {
		if config == nil {
			delete(*state, key)
		} else {
			(*state)[key] = *cloneLifecycle(config)
		}
		return nil
	})
}

func (w memoryWriter) AdvanceLifecycleScan(key BucketKey, due time.Time) error {
	return w.repository.lifecycle.Update(w.Context(), func(state *map[BucketKey]LifecycleConfiguration, _ *memory.Transaction) error {
		config, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		config.NextScan = new(due)
		(*state)[key] = config
		return nil
	})
}

func (w memoryWriter) TransitionObject(key ObjectVersionKey, storageClass string) (int64, error) {
	var sequence int64
	err := w.repository.objects.Update(w.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		object, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		var err error
		sequence, err = w.nextObjectSequence()
		if err != nil {
			return err
		}
		object.Sequence, object.StorageClass = sequence, storageClass
		(*state)[key] = object
		return nil
	})
	return sequence, err
}
