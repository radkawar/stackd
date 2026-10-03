package logs

import (
	"cmp"
	"maps"
	"slices"
	"strings"
)

func cloneDestination(v DestinationRecord) DestinationRecord {
	v.Tags = maps.Clone(v.Tags)
	return v
}
func (r memoryReader) Destination(k DestinationKey) (DestinationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return DestinationRecord{}, err
	}
	v, ok := r.state.destinations[k]
	if !ok {
		return v, ErrNotFound
	}
	return cloneDestination(v), nil
}
func (r memoryReader) Destinations(q DestinationQuery) ([]DestinationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []DestinationRecord{}
	for k, v := range r.state.destinations {
		if k.Scope == q.Scope && k.Name > q.After && strings.HasPrefix(k.Name, q.Prefix) {
			out = append(out, cloneDestination(v))
		}
	}
	slices.SortFunc(out, func(a, b DestinationRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func (w memoryWriter) PutDestination(v DestinationRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.destinations[v.Key] = cloneDestination(v)
	return nil
}
func (w memoryWriter) DeleteDestination(k DestinationKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.destinations, k)
	return nil
}
