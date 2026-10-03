package xray

import "cmp"

func (r memoryReader) NextGroupMetric() (GroupMetricRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return GroupMetricRecord{}, err
	}
	var next GroupMetricRecord
	found := false
	for key, count := range r.s.groupMetrics {
		if !found || compareGroupMetricKeys(key, next.Key) < 0 {
			next, found = GroupMetricRecord{Key: key, Count: count}, true
		}
	}
	if !found {
		return GroupMetricRecord{}, ErrNotFound
	}
	return next, nil
}

func compareGroupMetricKeys(a, b GroupMetricKey) int {
	return cmp.Or(a.Minute.Compare(b.Minute),
		cmp.Compare(a.Group.Partition, b.Group.Partition), cmp.Compare(a.Group.AccountID, b.Group.AccountID),
		cmp.Compare(a.Group.Region, b.Group.Region), cmp.Compare(a.Group.ID, b.Group.ID))
}

func (w memoryWriter) AddGroupMetric(key GroupMetricKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.groupMetrics[key]++
	return nil
}

func (w memoryWriter) DeleteGroupMetric(key GroupMetricKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.groupMetrics, key)
	return nil
}
