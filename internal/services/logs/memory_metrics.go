package logs

import (
	"cmp"
	"maps"
	"slices"
	"strings"
)

func cloneMetricFilter(v MetricFilterRecord) MetricFilterRecord {
	v.Dimensions = maps.Clone(v.Dimensions)
	v.EmitSystemFieldDimensions = slices.Clone(v.EmitSystemFieldDimensions)
	if v.DefaultValue != nil {
		value := *v.DefaultValue
		v.DefaultValue = &value
	}
	return v
}

func (r memoryReader) MetricFilter(k MetricFilterKey) (MetricFilterRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return MetricFilterRecord{}, err
	}
	v, ok := r.state.metricFilters[k]
	if !ok {
		return v, ErrNotFound
	}
	return cloneMetricFilter(v), nil
}

func (r memoryReader) MetricFilters(q MetricFilterQuery) ([]MetricFilterRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []MetricFilterRecord{}
	for k, v := range r.state.metricFilters {
		if q.GroupID != "" && k.GroupID != q.GroupID || !strings.HasPrefix(k.Name, q.Prefix) ||
			q.MetricName != "" && v.MetricName != q.MetricName || q.MetricNamespace != "" && v.MetricNamespace != q.MetricNamespace {
			continue
		}
		g, ok := r.state.groups[GroupKey{Scope: q.Scope, Name: v.GroupName}]
		if !ok || g.ID != k.GroupID || k.Name < q.AfterName || k.Name == q.AfterName && g.Key.Name <= q.AfterGroupName {
			continue
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b MetricFilterRecord) int {
		if order := cmp.Compare(a.Key.Name, b.Key.Name); order != 0 {
			return order
		}
		return cmp.Compare(a.GroupName, b.GroupName)
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	for i := range out {
		out[i] = cloneMetricFilter(out[i])
	}
	return out, nil
}

func (w memoryWriter) PutMetricFilter(v MetricFilterRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	found := false
	for _, g := range w.state.groups {
		if g.ID == v.Key.GroupID {
			v.GroupName = g.Key.Name
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	w.state.metricFilters[v.Key] = cloneMetricFilter(v)
	return nil
}

func (w memoryWriter) DeleteMetricFilter(k MetricFilterKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.metricFilters, k)
	return nil
}
