package lambda

import (
	"cmp"
	"slices"
	"stackd/storage/memory"
)

func (r memoryReader) StreamShards(k EventSourceMappingKey) (out []StreamShardRecord, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.streamShards.View(r.Context(), func(rows *map[StreamShardKey]StreamShardRecord, _ *memory.Transaction) error {
		for key, v := range *rows {
			if key.Mapping == k {
				out = append(out, cloneStreamShard(v))
			}
		}
		slices.SortFunc(out, func(a, b StreamShardRecord) int { return cmp.Compare(a.Key.ShardID, b.Key.ShardID) })
		return nil
	})
	return
}
func (w memoryWriter) PutStreamShard(v StreamShardRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if err := w.repository.mappings.View(w.Context(), func(rows *map[EventSourceMappingKey]EventSourceMappingRecord, _ *memory.Transaction) error {
		if _, ok := (*rows)[v.Key.Mapping]; !ok {
			return ErrNotFound
		}
		return nil
	}); err != nil {
		return err
	}
	return w.repository.streamShards.Update(w.Context(), func(rows *map[StreamShardKey]StreamShardRecord, _ *memory.Transaction) error {
		(*rows)[v.Key] = cloneStreamShard(v)
		return nil
	})
}
func (r memoryReader) StreamFailures() (out []StreamFailure, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.streamFailures.View(r.Context(), func(rows *map[string]StreamFailure, _ *memory.Transaction) error {
		for _, v := range *rows {
			v.Payload = slices.Clone(v.Payload)
			out = append(out, v)
		}
		slices.SortFunc(out, func(a, b StreamFailure) int { return cmp.Compare(a.ID, b.ID) })
		return nil
	})
	return
}
func (w memoryWriter) PutStreamFailure(v StreamFailure) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.streamFailures.Update(w.Context(), func(rows *map[string]StreamFailure, _ *memory.Transaction) error {
		v.Payload = slices.Clone(v.Payload)
		(*rows)[v.ID] = v
		return nil
	})
}
func (w memoryWriter) DeleteStreamFailure(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.streamFailures.Update(w.Context(), func(rows *map[string]StreamFailure, _ *memory.Transaction) error {
		delete(*rows, id)
		return nil
	})
}
