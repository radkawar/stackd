package lambda

import (
	"slices"
	"stackd/storage/memory"
)

func (r memoryReader) DocumentDBCheckpoint(k EventSourceMappingKey) (v DocumentDBCheckpoint, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.documentDBCheckpoints.View(r.Context(), func(rows *map[EventSourceMappingKey]DocumentDBCheckpoint, _ *memory.Transaction) error {
		var ok bool
		v, ok = (*rows)[k]
		if !ok {
			return ErrNotFound
		}
		v.ResumeToken = slices.Clone(v.ResumeToken)
		return nil
	})
	return
}
func (w memoryWriter) PutDocumentDBCheckpoint(v DocumentDBCheckpoint) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.documentDBCheckpoints.Update(w.Context(), func(rows *map[EventSourceMappingKey]DocumentDBCheckpoint, _ *memory.Transaction) error {
		v.ResumeToken = slices.Clone(v.ResumeToken)
		(*rows)[v.Mapping] = v
		return nil
	})
}
func (w memoryWriter) DeleteDocumentDBCheckpoint(k EventSourceMappingKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.documentDBCheckpoints.Update(w.Context(), func(rows *map[EventSourceMappingKey]DocumentDBCheckpoint, _ *memory.Transaction) error {
		delete(*rows, k)
		return nil
	})
}
