package s3

import (
	"time"

	"stackd/storage/memory"
)

func (w memoryWriter) ReplaceObjectRetention(key ObjectVersionKey, retention ObjectRetention) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	return w.repository.objects.Update(w.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		v, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		v.Retention = retention
		(*state)[key] = v
		return nil
	})
}

func (w memoryWriter) ReplaceObjectLegalHold(key ObjectVersionKey, status string, modified time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	return w.repository.objects.Update(w.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		v, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		v.LegalHold = status
		v.LegalHoldModified = modified
		(*state)[key] = v
		return nil
	})
}
