package eks

import (
	"cmp"
	"maps"
	"slices"
)

type addonKey struct {
	Key
	name string
}

func cloneAddon(a Addon) Addon { a.Tags = maps.Clone(a.Tags); return a }
func (r memoryReader) Addon(k Key, name string) (Addon, error) {
	if err := r.tx.Check(false); err != nil {
		return Addon{}, err
	}
	a, ok := r.s.addons[addonKey{k, name}]
	if !ok {
		return Addon{}, ErrNotFound
	}
	return cloneAddon(a), nil
}
func (r memoryReader) Addons(k Key) ([]Addon, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Addon{}
	for key, a := range r.s.addons {
		if key.Key == k {
			out = append(out, cloneAddon(a))
		}
	}
	slices.SortFunc(out, func(a, b Addon) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}
func (w memoryWriter) PutAddon(a Addon) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.addons[addonKey{a.Key, a.Name}] = cloneAddon(a)
	return nil
}
func (w memoryWriter) DeleteAddon(k Key, name string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.addons, addonKey{k, name})
	return nil
}
