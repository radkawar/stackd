package guardduty

import (
	"cmp"
	"maps"
	"slices"
	"sort"
)

type ipListKey struct {
	detectorKey
	Kind IPListKind
	ID   string
}

func cloneIPList(v IPList) IPList {
	v.Tags = maps.Clone(v.Tags)
	return v
}

func compareIPLists(a, b IPList) int {
	if n := cmp.Compare(a.Kind, b.Kind); n != 0 {
		return n
	}
	return cmp.Compare(a.ID, b.ID)
}

func (r memoryReader) IPList(sc Scope, detector string, kind IPListKind, id string) (IPList, error) {
	if err := r.t.Check(false); err != nil {
		return IPList{}, err
	}
	v, ok := r.s.ipLists[ipListKey{detectorKey{sc, detector}, kind, id}]
	if !ok {
		return IPList{}, ErrNotFound
	}
	return cloneIPList(v), nil
}

func (r memoryReader) IPLists(sc Scope, detector string) ([]IPList, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	var out []IPList
	for k, v := range r.s.ipLists {
		if k.detectorKey == (detectorKey{sc, detector}) {
			out = append(out, cloneIPList(v))
		}
	}
	slices.SortFunc(out, compareIPLists)
	return out, nil
}

func (r memoryReader) MatchingIPLists(sc Scope, detector string, ip uint32) ([]IPList, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	var out []IPList
	for k, v := range r.s.ipLists {
		if k.detectorKey != (detectorKey{sc, detector}) || v.Status != "ACTIVE" {
			continue
		}
		ranges := r.s.ipRanges[k]
		i := sort.Search(len(ranges), func(i int) bool { return ranges[i].Last >= ip })
		if i < len(ranges) && ranges[i].First <= ip {
			out = append(out, cloneIPList(v))
		}
	}
	slices.SortFunc(out, compareIPLists)
	return out, nil
}

func (w memoryWriter) PutIPList(v IPList) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	key := detectorKey{v.Scope, v.DetectorID}
	if _, ok := w.s.detectors[key]; !ok {
		return ErrNotFound
	}
	w.s.ipLists[ipListKey{key, v.Kind, v.ID}] = cloneIPList(v)
	return nil
}

func (w memoryWriter) DeleteIPList(sc Scope, detector string, kind IPListKind, id string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	key := ipListKey{detectorKey{sc, detector}, kind, id}
	delete(w.s.ipLists, key)
	delete(w.s.ipRanges, key)
	return nil
}

func (w memoryWriter) ReplaceIPRanges(sc Scope, detector string, kind IPListKind, id string, ranges []IPRange) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	key := ipListKey{detectorKey{sc, detector}, kind, id}
	if _, ok := w.s.ipLists[key]; !ok {
		return ErrNotFound
	}
	w.s.ipRanges[key] = slices.Clone(ranges)
	return nil
}
