package s3

import (
	"cmp"
	"errors"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type accessPointAliasKey struct{ partition, alias string }

func cloneAccessPoint(v AccessPointRecord) AccessPointRecord {
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	return v
}

func (r memoryReader) AccessPoint(key AccessPointKey) (AccessPointRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return AccessPointRecord{}, err
	}
	var out AccessPointRecord
	err := r.repository.accessPoints.View(r.Context(), func(state *map[AccessPointKey]AccessPointRecord, _ *memory.Transaction) error {
		v, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		out = cloneAccessPoint(v)
		return nil
	})
	return out, err
}

func (r memoryReader) AccessPointAlias(partition, alias string) (AccessPointRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return AccessPointRecord{}, err
	}
	var key AccessPointKey
	err := r.repository.accessPointAliases.View(r.Context(), func(state *map[accessPointAliasKey]AccessPointKey, _ *memory.Transaction) error {
		var ok bool
		key, ok = (*state)[accessPointAliasKey{partition: partition, alias: alias}]
		if !ok {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return AccessPointRecord{}, err
	}
	return r.AccessPoint(key)
}

func (r memoryReader) AccessPoints(query AccessPointQuery) ([]AccessPointRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []AccessPointRecord{}
	if query.Limit <= 0 {
		return out, nil
	}
	err := r.repository.accessPoints.View(r.Context(), func(state *map[AccessPointKey]AccessPointRecord, _ *memory.Transaction) error {
		for key, v := range *state {
			if key.Partition == query.Partition && key.AccountID == query.AccountID && key.Region == query.Region && key.Name > query.After && (query.Bucket == "" || v.Bucket.Name == query.Bucket) {
				out = append(out, v)
			}
		}
		slices.SortFunc(out, func(a, b AccessPointRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
		if len(out) > query.Limit {
			out = out[:query.Limit]
		}
		for i := range out {
			out[i] = cloneAccessPoint(out[i])
		}
		return nil
	})
	return out, err
}

func (r memoryReader) AccessPointCount(partition, accountID, region string) (int, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, err
	}
	var count int
	err := r.repository.accessPoints.View(r.Context(), func(state *map[AccessPointKey]AccessPointRecord, _ *memory.Transaction) error {
		for key := range *state {
			if key.Partition == partition && key.AccountID == accountID && key.Region == region {
				count++
			}
		}
		return nil
	})
	return count, err
}

func (r memoryReader) AccessPointTags(key AccessPointKey) ([]Tag, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []Tag
	err := r.repository.accessPoints.View(r.Context(), func(points *map[AccessPointKey]AccessPointRecord, _ *memory.Transaction) error {
		if _, exists := (*points)[key]; !exists {
			return ErrNotFound
		}
		return r.repository.accessPointTags.View(r.Context(), func(state *map[AccessPointKey][]Tag, _ *memory.Transaction) error {
			out = slices.Clone((*state)[key])
			return nil
		})
	})
	return out, err
}

func (w memoryWriter) PutAccessPoint(v AccessPointRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.accessPoints.Update(w.Context(), func(state *map[AccessPointKey]AccessPointRecord, _ *memory.Transaction) error {
		if err := w.repository.accessPointAliases.Update(w.Context(), func(aliases *map[accessPointAliasKey]AccessPointKey, _ *memory.Transaction) error {
			alias := accessPointAliasKey{partition: v.Key.Partition, alias: v.Alias}
			if key, exists := (*aliases)[alias]; exists && key != v.Key {
				return errors.New("S3 access point alias already exists")
			}
			if old, exists := (*state)[v.Key]; exists && old.Alias != v.Alias {
				delete(*aliases, accessPointAliasKey{partition: v.Key.Partition, alias: old.Alias})
			}
			(*aliases)[alias] = v.Key
			return nil
		}); err != nil {
			return err
		}
		(*state)[v.Key] = cloneAccessPoint(v)
		return nil
	})
}

func (w memoryWriter) DeleteAccessPoint(key AccessPointKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.accessPoints.Update(w.Context(), func(state *map[AccessPointKey]AccessPointRecord, _ *memory.Transaction) error {
		v, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		if err := w.repository.accessPointAliases.Update(w.Context(), func(aliases *map[accessPointAliasKey]AccessPointKey, _ *memory.Transaction) error {
			delete(*aliases, accessPointAliasKey{partition: key.Partition, alias: v.Alias})
			return nil
		}); err != nil {
			return err
		}
		if err := w.repository.accessPointTags.Update(w.Context(), func(tags *map[AccessPointKey][]Tag, _ *memory.Transaction) error {
			delete(*tags, key)
			return nil
		}); err != nil {
			return err
		}
		delete(*state, key)
		return nil
	})
}

func (w memoryWriter) PutAccessPointTags(key AccessPointKey, tags []Tag) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.accessPoints.View(w.Context(), func(points *map[AccessPointKey]AccessPointRecord, _ *memory.Transaction) error {
		if _, exists := (*points)[key]; !exists {
			return ErrNotFound
		}
		return w.repository.accessPointTags.Update(w.Context(), func(state *map[AccessPointKey][]Tag, _ *memory.Transaction) error {
			if len(tags) == 0 {
				delete(*state, key)
				return nil
			}
			out := slices.Clone(tags)
			slices.SortFunc(out, func(a, b Tag) int { return cmp.Compare(a.Key, b.Key) })
			for i := 1; i < len(out); i++ {
				if out[i-1].Key == out[i].Key {
					return errors.New("S3 access point tag key already exists")
				}
			}
			(*state)[key] = out
			return nil
		})
	})
}
