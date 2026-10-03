package eventbridge

import "slices"

func cloneReplay(v ReplayRecord) ReplayRecord {
	v.FilterARNs = slices.Clone(v.FilterARNs)
	return v
}

func (r memoryReader) Replay(k ReplayKey) (ReplayRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ReplayRecord{}, err
	}
	v, ok := r.s.replays[k]
	if !ok {
		return ReplayRecord{}, ErrNotFound
	}
	return cloneReplay(v), nil
}

func (r memoryReader) Replays(scope Scope) ([]ReplayRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ReplayRecord{}
	for k, v := range r.s.replays {
		if k.Scope == scope {
			out = append(out, cloneReplay(v))
		}
	}
	slices.SortFunc(out, func(a, b ReplayRecord) int { return compare(a.Key.Name, b.Key.Name) })
	return out, nil
}

func compareReplayKey(a, b ReplayKey) int {
	if n := compare(a.Partition, b.Partition); n != 0 {
		return n
	}
	if n := compare(a.Account, b.Account); n != 0 {
		return n
	}
	if n := compare(a.Region, b.Region); n != 0 {
		return n
	}
	return compare(a.Name, b.Name)
}

func (r memoryReader) NextReplay() (ReplayRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return ReplayRecord{}, false, err
	}
	var next ReplayRecord
	found := false
	for _, v := range r.s.replays {
		if v.State != "STARTING" && v.State != "RUNNING" && v.State != "CANCELLING" {
			continue
		}
		if !found || v.Due.Before(next.Due) || v.Due.Equal(next.Due) && compareReplayKey(v.Key, next.Key) < 0 {
			next, found = v, true
		}
	}
	return cloneReplay(next), found, nil
}

func (r memoryReader) NextReplayExpiration() (ReplayRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return ReplayRecord{}, false, err
	}
	var next ReplayRecord
	found := false
	for _, v := range r.s.replays {
		if v.Finished.IsZero() || v.State != "COMPLETED" && v.State != "CANCELLED" && v.State != "FAILED" {
			continue
		}
		// Adding the same 90-day history interval preserves this ordering.
		if !found || v.Finished.Before(next.Finished) || v.Finished.Equal(next.Finished) && compareReplayKey(v.Key, next.Key) < 0 {
			next, found = v, true
		}
	}
	return cloneReplay(next), found, nil
}

func (w memoryWriter) PutReplay(v ReplayRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.replays[v.Key] = cloneReplay(v)
	return nil
}

func (w memoryWriter) DeleteReplay(k ReplayKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.replays, k)
	return nil
}
