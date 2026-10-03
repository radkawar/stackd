package s3

import (
	"cmp"
	"slices"

	"stackd/storage/memory"
)

func (r memoryReader) ObjectTags(key ObjectVersionKey) ([]Tag, error) {
	var out []Tag
	err := r.repository.objectTags.View(r.Context(), func(state *map[ObjectVersionKey][]Tag, _ *memory.Transaction) error {
		out = slices.Clone((*state)[key])
		return nil
	})
	return out, err
}

func (w memoryWriter) ReplaceObjectTags(key ObjectVersionKey, tags []Tag) error {
	return w.repository.objectTags.Update(w.Context(), func(state *map[ObjectVersionKey][]Tag, _ *memory.Transaction) error {
		if len(tags) == 0 {
			delete(*state, key)
		} else {
			stored := slices.Clone(tags)
			slices.SortFunc(stored, func(a, b Tag) int { return cmp.Compare(a.Key, b.Key) })
			(*state)[key] = stored
		}
		return nil
	})
}
