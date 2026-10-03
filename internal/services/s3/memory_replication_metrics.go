package s3

import (
	"cmp"
	"time"

	"stackd/storage/memory"
)

type memoryReplicationMetricKey struct {
	Key ReplicationMetricKey
	At  time.Time
}

func (r memoryReader) NextReplicationMetricPublication() (*ReplicationMetricPublication, error) {
	var out ReplicationMetricPublication
	found := false
	err := r.repository.replicationMetrics.View(r.Context(), func(state *map[memoryReplicationMetricKey]ReplicationMetricPublication, _ *memory.Transaction) error {
		for _, value := range *state {
			if !found || compareReplicationMetricPublications(value, out) < 0 {
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

func compareReplicationMetricPublications(a, b ReplicationMetricPublication) int {
	return cmp.Or(
		a.Deadline().Compare(b.Deadline()),
		a.At.Compare(b.At),
		cmp.Compare(a.Key.Source.Partition, b.Key.Source.Partition),
		cmp.Compare(a.Key.Source.Name, b.Key.Source.Name),
		cmp.Compare(a.Key.Destination.Partition, b.Key.Destination.Partition),
		cmp.Compare(a.Key.Destination.Name, b.Key.Destination.Name),
		cmp.Compare(a.Key.AccountID, b.Key.AccountID),
		cmp.Compare(a.Key.SourceRegion, b.Key.SourceRegion),
		cmp.Compare(a.Key.DestinationRegion, b.Key.DestinationRegion),
		cmp.Compare(a.Key.RuleID, b.Key.RuleID),
	)
}

func (r memoryReader) ReplicationMetricPublication(key ReplicationMetricKey, at time.Time) (*ReplicationMetricPublication, error) {
	var out *ReplicationMetricPublication
	err := r.repository.replicationMetrics.View(r.Context(), func(state *map[memoryReplicationMetricKey]ReplicationMetricPublication, _ *memory.Transaction) error {
		if value, ok := (*state)[memoryReplicationMetricKey{Key: key, At: at.UTC()}]; ok {
			out = &value
		}
		return nil
	})
	return out, err
}

func (r memoryReader) ReplicationPending(key ReplicationMetricKey, at time.Time) (ReplicationPending, error) {
	var out ReplicationPending
	err := r.repository.replicationJobs.View(r.Context(), func(jobs *map[int64]ReplicationJob, _ *memory.Transaction) error {
		bucket, ok := (*r.state)[key.Source]
		if !ok || bucket.AccountID != key.AccountID {
			return nil
		}
		return r.repository.objects.View(r.Context(), func(objects *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
			for _, job := range *jobs {
				if job.Source.Bucket != key.Source || job.Destination.Bucket != key.Destination || job.RuleID != key.RuleID || job.Created.After(at) {
					continue
				}
				source, ok := (*objects)[job.Source]
				if !ok {
					continue
				}
				if out.Operations == 0 || job.Created.Before(out.Oldest) {
					out.Oldest = job.Created
				}
				out.Operations++
				if job.Operation == ReplicationObject {
					out.Bytes += source.Size
				}
			}
			return nil
		})
	})
	return out, err
}

func (w memoryWriter) ReplaceReplicationMetricSchedules(source BucketKey, rows []ReplicationMetricPublication) error {
	return w.repository.replicationMetrics.Update(w.Context(), func(state *map[memoryReplicationMetricKey]ReplicationMetricPublication, _ *memory.Transaction) error {
		for key, value := range *state {
			if key.Key.Source != source {
				continue
			}
			if value.Recurring {
				value.Recurring = false
				(*state)[key] = value
			}
		}
		for _, row := range rows {
			key := memoryReplicationMetricKey{Key: row.Key, At: row.At.UTC()}
			value := (*state)[key]
			if !value.Sampled && value.Operations == 0 {
				value = ReplicationMetricPublication{Key: key.Key, At: key.At, ReadyAt: row.ReadyAt.UTC()}
			}
			value.Recurring = !value.Sampled
			(*state)[key] = value
		}
		for key, value := range *state {
			if key.Key.Source == source && !value.Recurring && !value.Sampled && value.Operations == 0 {
				delete(*state, key)
			}
		}
		return nil
	})
}

func (w memoryWriter) AddReplicationMetricOutcome(key ReplicationMetricKey, at, readyAt time.Time, failed bool) error {
	return w.repository.replicationMetrics.Update(w.Context(), func(state *map[memoryReplicationMetricKey]ReplicationMetricPublication, _ *memory.Transaction) error {
		storageKey := memoryReplicationMetricKey{Key: key, At: at.UTC()}
		value, exists := (*state)[storageKey]
		if !exists {
			value = ReplicationMetricPublication{Key: key, At: storageKey.At, ReadyAt: readyAt.UTC()}
		}
		value.Operations++
		if failed {
			value.Failed++
		}
		(*state)[storageKey] = value
		return nil
	})
}

func (w memoryWriter) SampleReplicationMetricPublication(publication ReplicationMetricPublication) error {
	return w.repository.replicationMetrics.Update(w.Context(), func(state *map[memoryReplicationMetricKey]ReplicationMetricPublication, _ *memory.Transaction) error {
		key := memoryReplicationMetricKey{Key: publication.Key, At: publication.At.UTC()}
		value, ok := (*state)[key]
		if !ok || !value.Recurring {
			return nil
		}
		value.Recurring = false
		value.Sampled = true
		value.Pending = publication.Pending
		(*state)[key] = value

		key.At = key.At.Add(time.Minute)
		next, exists := (*state)[key]
		if !exists {
			next = ReplicationMetricPublication{Key: key.Key, At: key.At, ReadyAt: value.ReadyAt}
		}
		next.Recurring = !next.Sampled
		(*state)[key] = next
		return nil
	})
}

func (w memoryWriter) CompleteReplicationMetricPublication(publication ReplicationMetricPublication) error {
	return w.repository.replicationMetrics.Update(w.Context(), func(state *map[memoryReplicationMetricKey]ReplicationMetricPublication, _ *memory.Transaction) error {
		delete(*state, memoryReplicationMetricKey{Key: publication.Key, At: publication.At.UTC()})
		return nil
	})
}
