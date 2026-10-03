package lambda

import (
	"slices"
	"time"

	"stackd/storage/memory"
)

func (r memoryReader) CodeArchive(key CodeArchiveKey) (CodeArchive, error) {
	if err := r.tx.Check(false); err != nil {
		return CodeArchive{}, err
	}
	var archive CodeArchive
	err := r.repository.archives.View(r.Context(), func(state *map[CodeArchiveKey]CodeArchive, _ *memory.Transaction) error {
		var ok bool
		archive, ok = (*state)[key]
		if !ok {
			return ErrNotFound
		}
		archive.Code = slices.Clone(archive.Code)
		return nil
	})
	return archive, err
}

func (r memoryReader) CodeSigningKey(scope Scope) (CodeSigningKey, error) {
	if err := r.tx.Check(false); err != nil {
		return CodeSigningKey{}, err
	}
	var key CodeSigningKey
	err := r.repository.signingKeys.View(r.Context(), func(state *map[Scope]CodeSigningKey, _ *memory.Transaction) error {
		var ok bool
		key, ok = (*state)[scope]
		if !ok {
			return ErrNotFound
		}
		return nil
	})
	return key, err
}

func (r memoryReader) referencedCodeArchives() (map[CodeArchiveKey]struct{}, error) {
	keys := make(map[CodeArchiveKey]struct{}, len(*r.state))
	for _, function := range *r.state {
		keys[CodeArchiveKey{Scope: function.Key.Scope, SHA256: function.CodeSHA256}] = struct{}{}
	}
	layers, err := r.layerCodeReferences()
	if err != nil {
		return nil, err
	}
	for _, layer := range layers {
		keys[CodeArchiveKey{Scope: layer.Key.Scope, SHA256: layer.CodeSHA256}] = struct{}{}
	}
	return keys, nil
}

func (r memoryReader) NextCodeArchiveDeadline() (time.Time, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return time.Time{}, false, err
	}
	referenced, err := r.referencedCodeArchives()
	if err != nil {
		return time.Time{}, false, err
	}
	var deadline time.Time
	var found bool
	err = r.repository.archives.View(r.Context(), func(state *map[CodeArchiveKey]CodeArchive, _ *memory.Transaction) error {
		for key, archive := range *state {
			if _, ok := referenced[key]; ok {
				continue
			}
			next := archive.RetainUntil.Add(time.Nanosecond)
			if !found || next.Before(deadline) {
				deadline, found = next, true
			}
		}
		return nil
	})
	return deadline, found, err
}

func (w memoryWriter) PutCodeArchive(archive CodeArchive) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.archives.Update(w.Context(), func(state *map[CodeArchiveKey]CodeArchive, _ *memory.Transaction) error {
		if existing, ok := (*state)[archive.Key]; ok {
			if archive.RetainUntil.After(existing.RetainUntil) {
				existing.RetainUntil = archive.RetainUntil
				(*state)[archive.Key] = existing
			}
			return nil
		}
		archive.Code = slices.Clone(archive.Code)
		(*state)[archive.Key] = archive
		return nil
	})
}

func (w memoryWriter) RetainCodeArchive(key CodeArchiveKey, until time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.archives.Update(w.Context(), func(state *map[CodeArchiveKey]CodeArchive, _ *memory.Transaction) error {
		archive, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		if until.After(archive.RetainUntil) {
			archive.RetainUntil = until
			(*state)[key] = archive
		}
		return nil
	})
}

func (w memoryWriter) PutCodeSigningKey(key CodeSigningKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.signingKeys.Update(w.Context(), func(state *map[Scope]CodeSigningKey, _ *memory.Transaction) error {
		if _, exists := (*state)[key.Scope]; !exists {
			(*state)[key.Scope] = key
		}
		return nil
	})
}

func (w memoryWriter) DeleteExpiredCodeArchives(now time.Time) (int64, error) {
	if err := w.tx.Check(true); err != nil {
		return 0, err
	}
	referenced, err := w.referencedCodeArchives()
	if err != nil {
		return 0, err
	}
	var deleted int64
	err = w.repository.archives.Update(w.Context(), func(state *map[CodeArchiveKey]CodeArchive, _ *memory.Transaction) error {
		for key, archive := range *state {
			if _, ok := referenced[key]; !ok && archive.RetainUntil.Before(now) {
				delete(*state, key)
				deleted++
			}
		}
		return nil
	})
	return deleted, err
}
