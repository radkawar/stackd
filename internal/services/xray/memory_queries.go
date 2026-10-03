package xray

import (
	"cmp"
	"maps"
	"slices"
)

type groupTraceKey struct {
	Group GroupKey
	Trace TraceKey
}

func cloneGroup(v GroupRecord) GroupRecord {
	v.Tags = maps.Clone(v.Tags)
	return v
}

func (r memoryReader) Trace(key TraceKey) (TraceRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TraceRecord{}, err
	}
	row, ok := r.s.traces[key]
	if !ok {
		return TraceRecord{}, ErrNotFound
	}
	return row, nil
}

func (w memoryWriter) PutTrace(row TraceRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.traces[row.Key] = row
	return nil
}

func (r memoryReader) Traces(selection TraceSelection) ([]TraceData, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	start, end := selection.TimeBounds()
	startSeconds := float64(start.Unix()) + float64(start.Nanosecond())/1e9
	endSeconds := float64(end.Unix()) + float64(end.Nanosecond())/1e9
	completions := make(map[TraceKey]bool)
	if selection.Kind == TraceCompletionTime {
		for key, segment := range r.s.segments {
			if key.Scope != selection.Scope {
				continue
			}
			var membership GroupMembership
			if selection.Group != nil {
				membership = r.s.groupTraces[groupTraceKey{Group: *selection.Group, Trace: key.TraceKey}]
			}
			if membership.IncludesCompletion(segment, start, end) {
				completions[key.TraceKey] = true
			}
		}
	}
	rows := make([]TraceData, 0)
	for key, record := range r.s.traces {
		if key.Scope != selection.Scope {
			continue
		}
		var matches bool
		switch selection.Kind {
		case TraceEventTime:
			matches = !record.Updated.Before(start) && !record.Updated.After(end)
		case TraceServiceTime:
			matches = record.End >= startSeconds && record.Start <= endSeconds
		case TraceCompletionTime:
			matches = completions[key]
		default:
			matches = record.Start >= startSeconds && record.Start <= endSeconds
		}
		if !matches {
			continue
		}
		var membership GroupMembership
		if selection.Group != nil {
			var found bool
			membership, found = r.s.groupTraces[groupTraceKey{Group: *selection.Group, Trace: key}]
			if !found {
				continue
			}
		}
		rows = append(rows, TraceData{Record: record, Segments: []SegmentRecord{}, Membership: membership})
	}
	slices.SortFunc(rows, func(a, b TraceData) int {
		if order := cmp.Compare(b.Record.Start, a.Record.Start); order != 0 {
			return order
		}
		return cmp.Compare(a.Record.Key.ID, b.Record.Key.ID)
	})
	positions := make(map[TraceKey]int, len(rows))
	for i := range rows {
		positions[rows[i].Record.Key] = i
	}
	for key, segment := range r.s.segments {
		if i, found := positions[key.TraceKey]; found {
			rows[i].Segments = append(rows[i].Segments, cloneSegment(segment))
		}
	}
	for i := range rows {
		slices.SortFunc(rows[i].Segments, func(a, b SegmentRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	}
	return rows, nil
}

func (r memoryReader) Group(key GroupKey) (GroupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return GroupRecord{}, err
	}
	row, ok := r.s.groups[key]
	if !ok {
		return GroupRecord{}, ErrNotFound
	}
	return cloneGroup(row), nil
}

func (r memoryReader) Groups(scope Scope) ([]GroupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]GroupRecord, 0)
	for key, row := range r.s.groups {
		if key.Scope == scope {
			rows = append(rows, cloneGroup(row))
		}
	}
	slices.SortFunc(rows, func(a, b GroupRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return rows, nil
}

func (w memoryWriter) PutGroup(row GroupRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.groups[row.Key] = cloneGroup(row)
	return nil
}

func (w memoryWriter) AddGroupTrace(group GroupKey, trace TraceKey, membership GroupMembership) (bool, error) {
	if err := w.tx.Check(true); err != nil {
		return false, err
	}
	key := groupTraceKey{Group: group, Trace: trace}
	if _, exists := w.s.groupTraces[key]; exists {
		return false, nil
	}
	w.s.groupTraces[key] = membership
	return true, nil
}

func (w memoryWriter) DeleteGroup(key GroupKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.groups, key)
	for membership := range w.s.groupTraces {
		if membership.Group == key {
			delete(w.s.groupTraces, membership)
		}
	}
	return nil
}
