package cloudwatch

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type pointNode struct {
	points   []Point
	previous *pointNode
}

type memoryState struct {
	metrics           map[MetricKey]MetricRecord
	points            map[string]*pointNode
	alarms            map[string]AlarmRecord
	alarmNames        map[AlarmKey]string
	alarmContributors map[alarmContributorKey]AlarmContributorRecord
	alarmHistory      map[string]AlarmHistoryRecord
	alarmActions      map[string]AlarmActionRecord
	dashboards        map[DashboardKey]DashboardRecord
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{
		metrics: map[MetricKey]MetricRecord{}, points: map[string]*pointNode{},
		alarms: map[string]AlarmRecord{}, alarmNames: map[AlarmKey]string{},
		alarmContributors: map[alarmContributorKey]AlarmContributorRecord{},
		alarmHistory:      map[string]AlarmHistoryRecord{}, alarmActions: map[string]AlarmActionRecord{},
		dashboards: map[DashboardKey]DashboardRecord{},
	}
	return &MemoryRepository{memory.New(domain, initial, func(s memoryState) memoryState {
		return memoryState{
			metrics: maps.Clone(s.metrics), points: maps.Clone(s.points),
			alarms: maps.Clone(s.alarms), alarmNames: maps.Clone(s.alarmNames),
			alarmContributors: maps.Clone(s.alarmContributors),
			alarmHistory:      maps.Clone(s.alarmHistory), alarmActions: maps.Clone(s.alarmActions),
			dashboards: maps.Clone(s.dashboards),
		}
	})}
}

func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error {
		return fn(memoryReader{s, tx})
	})
}

func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error {
		return fn(memoryWriter{memoryReader{s, tx}})
	})
}

func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, tx *memory.Transaction) error {
		return fn(memoryWriter{memoryReader{s, tx}})
	})
}

type memoryReader struct {
	state *memoryState
	tx    *memory.Transaction
}

type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }

func cloneMetric(v MetricRecord) MetricRecord {
	v.Dimensions = slices.Clone(v.Dimensions)
	return v
}

func (r memoryReader) Metric(key MetricKey) (MetricRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return MetricRecord{}, err
	}
	v, ok := r.state.metrics[key]
	if !ok {
		return MetricRecord{}, ErrNotFound
	}
	return cloneMetric(v), nil
}

func compareMetricKeys(a, b MetricKey) int {
	if n := cmp.Compare(a.Namespace, b.Namespace); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Name, b.Name); n != 0 {
		return n
	}
	return cmp.Compare(a.Dimensions, b.Dimensions)
}

func (r memoryReader) Metrics(q MetricQuery) ([]MetricRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []MetricRecord{}
	if q.Limit <= 0 {
		return out, nil
	}
	for key, metric := range r.state.metrics {
		if key.Scope != q.Scope || q.Namespace != "" && key.Namespace != q.Namespace || q.Name != "" && key.Name != q.Name {
			continue
		}
		if q.After != nil && compareMetricKeys(key, *q.After) <= 0 || !q.PublishedAfter.IsZero() && !metric.PublishedAt.After(q.PublishedAfter) {
			continue
		}
		matches := true
		for _, filter := range q.Dimensions {
			found := false
			for _, dimension := range metric.Dimensions {
				if dimension.Name == filter.Name && (filter.Value == nil || dimension.Value == *filter.Value) {
					found = true
					break
				}
			}
			if !found {
				matches = false
				break
			}
		}
		if matches {
			out = append(out, metric)
		}
	}
	slices.SortFunc(out, func(a, b MetricRecord) int { return compareMetricKeys(a.Key, b.Key) })
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	for i := range out {
		out[i] = cloneMetric(out[i])
	}
	return out, nil
}

func (r memoryReader) Points(q PointQuery, visit func(Point) error) error {
	if err := r.tx.Check(false); err != nil {
		return err
	}
	// Immutable chunks preserve publication order and share old observations
	// across transaction snapshots without copying the metric's full history.
	var chunks []*pointNode
	for node := r.state.points[q.MetricID]; node != nil; node = node.previous {
		chunks = append(chunks, node)
	}
	for i := len(chunks) - 1; i >= 0; i-- {
		if err := r.Context().Err(); err != nil {
			return err
		}
		for _, point := range chunks[i].points {
			if point.Timestamp >= q.Start && point.Timestamp < q.End {
				if err := visit(point); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (w memoryWriter) PutMetric(v MetricRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.metrics[v.Key] = cloneMetric(v)
	return nil
}

func (w memoryWriter) AppendPoints(metricID string, points []Point) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.points[metricID] = &pointNode{points: slices.Clone(points), previous: w.state.points[metricID]}
	return nil
}
