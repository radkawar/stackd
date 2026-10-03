package cloudwatch

import (
	"cmp"
	"maps"
	"slices"
	"strings"
)

func (r memoryReader) Dashboard(key DashboardKey) (DashboardRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return DashboardRecord{}, err
	}
	record, ok := r.state.dashboards[key]
	if !ok {
		return DashboardRecord{}, ErrNotFound
	}
	record.Tags = maps.Clone(record.Tags)
	return record, nil
}

func (r memoryReader) Dashboards(query DashboardQuery) ([]DashboardEntry, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []DashboardEntry{}
	if query.Limit <= 0 {
		return out, nil
	}
	for key, record := range r.state.dashboards {
		if key.Partition == query.Partition && key.AccountID == query.AccountID && key.Name > query.After && strings.HasPrefix(key.Name, query.Prefix) {
			out = append(out, record.DashboardEntry)
		}
	}
	slices.SortFunc(out, func(a, b DashboardEntry) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	if len(out) > query.Limit {
		out = out[:query.Limit]
	}
	return out, nil
}

func (w memoryWriter) PutDashboard(record DashboardRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	record.Tags = maps.Clone(record.Tags)
	w.state.dashboards[record.Key] = record
	return nil
}

func (w memoryWriter) DeleteDashboard(key DashboardKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.dashboards, key)
	return nil
}
