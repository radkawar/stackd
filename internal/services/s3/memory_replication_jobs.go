package s3

import (
	"cmp"
	"slices"
	"time"

	"stackd/storage/memory"
)

type memoryReplicationStateKey struct {
	Source      ObjectVersionKey
	Destination BucketKey
	Operation   ReplicationOperation
}

func (r memoryReader) ReplicationStates(source ObjectVersionKey) ([]ReplicationState, error) {
	if source.VersionID == "" {
		source.VersionID = "null"
	}
	var out []ReplicationState
	err := r.repository.replicationStates.View(r.Context(), func(state *map[memoryReplicationStateKey]ReplicationState, _ *memory.Transaction) error {
		for key, value := range *state {
			if key.Source == source {
				out = append(out, value)
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b ReplicationState) int {
		return cmp.Or(
			cmp.Compare(a.Destination.Partition, b.Destination.Partition),
			cmp.Compare(a.Destination.Name, b.Destination.Name),
			cmp.Compare(a.Operation, b.Operation),
		)
	})
	return out, err
}

func cloneReplicationJob(job ReplicationJob) ReplicationJob {
	job.Destination = cloneReplicationDestination(job.Destination)
	return job
}

func (r memoryReader) ReplicationJob(sequence int64) (ReplicationJob, error) {
	var out ReplicationJob
	err := r.repository.replicationJobs.View(r.Context(), func(state *map[int64]ReplicationJob, _ *memory.Transaction) error {
		value, ok := (*state)[sequence]
		if !ok {
			return ErrNotFound
		}
		out = cloneReplicationJob(value)
		return nil
	})
	return out, err
}

func (r memoryReader) ReplicationJobs(source ObjectVersionKey) ([]ReplicationJob, error) {
	if source.VersionID == "" {
		source.VersionID = "null"
	}
	var out []ReplicationJob
	err := r.repository.replicationJobs.View(r.Context(), func(state *map[int64]ReplicationJob, _ *memory.Transaction) error {
		for _, job := range *state {
			if job.Source == source {
				out = append(out, cloneReplicationJob(job))
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b ReplicationJob) int {
		return cmp.Compare(a.Sequence, b.Sequence)
	})
	return out, err
}

func (r memoryReader) NextReplicationJob() (*ReplicationJob, error) {
	var out ReplicationJob
	var current time.Time
	found := false
	err := r.repository.replicationJobs.View(r.Context(), func(state *map[int64]ReplicationJob, _ *memory.Transaction) error {
		for _, value := range *state {
			deadline := value.Deadline()
			if !found || deadline.Before(current) || (deadline.Equal(current) && value.Sequence < out.Sequence) {
				out = value
				current = deadline
				found = true
			}
		}
		return nil
	})
	if err != nil || !found {
		return nil, err
	}
	out = cloneReplicationJob(out)
	return &out, nil
}

func (w memoryWriter) PutReplicationState(value ReplicationState) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if value.Source.VersionID == "" {
		value.Source.VersionID = "null"
	}
	return w.repository.objects.View(w.Context(), func(objects *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		if _, ok := (*objects)[value.Source]; !ok {
			return ErrNotFound
		}
		return w.repository.replicationStates.Update(w.Context(), func(state *map[memoryReplicationStateKey]ReplicationState, _ *memory.Transaction) error {
			key := memoryReplicationStateKey{Source: value.Source, Destination: value.Destination, Operation: value.Operation}
			if previous, ok := (*state)[key]; !ok || value.Sequence >= previous.Sequence {
				(*state)[key] = value
			}
			return nil
		})
	})
}

func (w memoryWriter) PutReplicationJob(job *ReplicationJob) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	value := *job
	if value.Source.VersionID == "" {
		value.Source.VersionID = "null"
	}
	return w.repository.replicationJobs.Update(w.Context(), func(state *map[int64]ReplicationJob, _ *memory.Transaction) error {
		if previous, ok := (*state)[value.Sequence]; ok {
			previous.Due = value.Due
			previous.Attempts = value.Attempts
			previous.ThresholdReported = value.ThresholdReported
			(*state)[value.Sequence] = previous
			return nil
		}
		return w.repository.objects.View(w.Context(), func(objects *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
			if _, ok := (*objects)[value.Source]; !ok {
				return ErrNotFound
			}
			if value.Sequence == 0 {
				var err error
				value.Sequence, err = w.nextObjectSequence()
				if err != nil {
					return err
				}
				job.Sequence = value.Sequence
			}
			(*state)[value.Sequence] = cloneReplicationJob(value)
			return nil
		})
	})
}

func (w memoryWriter) DeleteReplicationJob(sequence int64) error {
	return w.repository.replicationJobs.Update(w.Context(), func(state *map[int64]ReplicationJob, _ *memory.Transaction) error {
		delete(*state, sequence)
		return nil
	})
}

// Replication work is owned only by its source version, never by configuration
// or destination lifetime. Null replacement removes the previous version's work.
func (w memoryWriter) deleteReplicationWhere(matches func(ObjectVersionKey) bool) error {
	if err := w.repository.replicationStates.Update(w.Context(), func(state *map[memoryReplicationStateKey]ReplicationState, _ *memory.Transaction) error {
		for key := range *state {
			if matches(key.Source) {
				delete(*state, key)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return w.repository.replicationJobs.Update(w.Context(), func(state *map[int64]ReplicationJob, _ *memory.Transaction) error {
		for sequence, job := range *state {
			if matches(job.Source) {
				delete(*state, sequence)
			}
		}
		return nil
	})
}

func (w memoryWriter) PutReplica(source ObjectVersionKey, replica ObjectRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if source.VersionID == "" {
		source.VersionID = "null"
	}
	parts, err := w.ObjectParts(source)
	if err != nil {
		return err
	}
	var data [][]byte
	if err := w.repository.data.View(w.Context(), func(state *map[ObjectVersionKey][][]byte, _ *memory.Transaction) error {
		payload, ok := (*state)[source]
		if !ok {
			return ErrNotFound
		}
		// Retain independent part references, not a link to the source record.
		// Ciphertext is immutable; only detached public reads copy its bytes.
		data = slices.Clone(payload)
		return nil
	}); err != nil {
		return err
	}
	if err := w.insertObjectRecord(&replica, false); err != nil {
		return err
	}
	key := replica.VersionKey()
	if err := w.ReplaceObjectTags(key, nil); err != nil {
		return err
	}
	if err := w.repository.objectParts.Update(w.Context(), func(state *map[ObjectVersionKey][]PartRecord, _ *memory.Transaction) error {
		(*state)[key] = parts
		return nil
	}); err != nil {
		return err
	}
	return w.repository.data.Update(w.Context(), func(state *map[ObjectVersionKey][][]byte, _ *memory.Transaction) error {
		(*state)[key] = data
		return nil
	})
}
