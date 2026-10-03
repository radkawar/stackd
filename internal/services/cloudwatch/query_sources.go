package cloudwatch

import (
	"errors"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

type metricReadSource struct {
	metric   *queryMetric
	metricID string
	unit     string
	bounds   metricQueryBounds
	series   *mathSeries
	messages api.MetricDataResultMessages
}

type metricQuerySources struct {
	direct   []*metricReadSource
	searches map[*mathNode][]*metricReadSource
	ordered  []*metricReadSource
	messages api.MetricDataResultMessages
}

type metricQueryPage struct {
	limit      int64
	descending bool
	offsets    []int64
	more       bool
}

func prepareMetricSources(r Reader, scope Scope, queries api.MetricDataQueries, plan *metricQueryPlan, now time.Time, window metricQueryWindow) (*metricQuerySources, *awswire.Error) {
	out := &metricQuerySources{direct: make([]*metricReadSource, len(queries)), searches: make(map[*mathNode][]*metricReadSource, len(plan.searches))}
	active := activeMetricQueries(queries, plan)
	var labelled []*metricReadSource
	for i, query := range queries {
		if query.MetricStat == nil {
			continue
		}
		metric := &plan.compiled[i]
		source := &metricReadSource{metric: metric, unit: value(query.MetricStat.Unit), bounds: window(metric.period, false)}
		source.series = &mathSeries{period: metric.period, label: metric.key.Name, metric: true, identity: metric, values: map[int64]float64{}}
		out.direct[i] = source
		if !active[i] {
			continue
		}
		if metric.key.AccountID != scope.AccountID {
			source.bounds.available = false
		} else if source.bounds.available {
			record, err := r.Metric(metric.key)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return nil, wireError(err)
			}
			source.metricID = record.ID
		}
		out.ordered = append(out.ordered, source)
		if query.Label == nil && (query.ReturnData == nil || bool(*query.ReturnData)) {
			labelled = append(labelled, source)
		}
	}
	for _, node := range plan.searches {
		search := node.search
		bounds := window(search.period, false)
		out.searches[node] = []*metricReadSource{}
		if !bounds.available {
			continue
		}
		selection := MetricQuery{Scope: scope, Namespace: search.namespace, PublishedAfter: now.Add(-14 * 24 * time.Hour), Limit: 500}
		if selection.Namespace == "" {
			selection.Namespace = search.term.exactProperty("Namespace")
		}
		selection.Name = search.term.exactProperty("MetricName")
		var records []MetricRecord
		for len(records) <= 500 {
			batch, err := r.Metrics(selection)
			if err != nil {
				return nil, wireError(err)
			}
			for _, record := range batch {
				if search.matches(record) {
					records = append(records, record)
					if len(records) > 500 {
						break
					}
				}
			}
			if len(batch) < selection.Limit {
				break
			}
			selection.After = &batch[len(batch)-1].Key
		}
		if len(records) > 500 {
			out.messages = append(out.messages, dataMessage("MaxMetricsExceeded", "Maximum number of allowed metrics exceeded"))
			records = records[:500]
		}
		metrics := make([]queryMetric, len(records))
		for i, record := range records {
			metrics[i] = queryMetric{key: record.Key, dimensions: record.Dimensions, statistic: search.statistic, period: search.period}
		}
		sources := make([]*metricReadSource, len(records))
		for i, record := range records {
			metric := &metrics[i]
			series := &mathSeries{period: metric.period, metric: true, identity: metric, values: map[int64]float64{}}
			sources[i] = &metricReadSource{metric: metric, metricID: record.ID, bounds: bounds, series: series}
		}
		out.searches[node] = sources
		labelled = append(labelled, sources...)
	}
	labels := automaticMetricLabels(labelled)
	for i, source := range labelled {
		source.series.label = labels[i]
	}
	for _, node := range plan.searches {
		sources := out.searches[node]
		slices.SortStableFunc(sources, func(a, b *metricReadSource) int { return strings.Compare(a.series.label, b.series.label) })
		out.ordered = append(out.ordered, sources...)
	}
	return out, nil
}

func activeMetricQueries(queries api.MetricDataQueries, plan *metricQueryPlan) []bool {
	active := make([]bool, len(queries))
	var visitQuery func(int)
	var visitNode func(*mathNode)
	visitQuery = func(index int) {
		if active[index] {
			return
		}
		active[index] = true
		visitNode(plan.nodes[index])
	}
	visitNode = func(node *mathNode) {
		if node == nil {
			return
		}
		if node.kind == "name" {
			if index, exists := plan.indices[node.text]; exists {
				visitQuery(index)
			}
		}
		if node.kind == "call" && node.text == "METRICS" {
			filter := ""
			if len(node.args) == 1 && node.args[0].kind == "string" {
				filter = node.args[0].text
			}
			for i, query := range queries {
				if query.MetricStat != nil && strings.Contains(value(query.Id), filter) {
					visitQuery(i)
				}
			}
		}
		for _, child := range node.args {
			visitNode(child)
		}
	}
	for i, query := range queries {
		if query.ReturnData == nil || bool(*query.ReturnData) {
			visitQuery(i)
		}
	}
	return active
}

// Pagination owns retrieval slots, before math executes. Empty slots consume
// budget; derived expressions and Insights do not introduce additional sources.
func (sources *metricQuerySources) read(r Reader, page *metricQueryPage, readBuckets metricBucketReader) *awswire.Error {
	if page == nil {
		for _, source := range sources.ordered {
			if w := source.read(r, readBuckets); w != nil {
				return w
			}
		}
		return nil
	}
	if page.offsets == nil {
		page.offsets = make([]int64, len(sources.ordered))
	} else if len(page.offsets) != len(sources.ordered) {
		return failure("InvalidNextToken", "")
	}
	remaining := make([]int64, len(sources.ordered))
	active := int64(0)
	for i, source := range sources.ordered {
		total := int64(0)
		if source.bounds.available && source.bounds.end > source.bounds.start {
			total = (source.bounds.end - source.bounds.start + source.metric.period - 1) / source.metric.period
		}
		offset := page.offsets[i]
		if offset < 0 || offset > total {
			return failure("InvalidNextToken", "")
		}
		remaining[i] = total - offset
		source.series.omitted = offset > 0 && remaining[i] == 0
		if remaining[i] > 0 {
			active++
		}
	}
	share := int64(0)
	if active > 0 {
		share = page.limit / active
	}
	allocated := make([]int64, len(remaining))
	left := page.limit
	for i, slots := range remaining {
		allocated[i] = min(slots, share)
		left -= allocated[i]
	}
	for i, slots := range remaining {
		extra := min(left, slots-allocated[i])
		allocated[i] += extra
		left -= extra
	}
	for i, source := range sources.ordered {
		period := source.metric.period
		start := source.bounds.start
		if page.descending {
			source.bounds.start = start + (remaining[i]-allocated[i])*period
			source.bounds.end = min(source.bounds.end, start+remaining[i]*period)
		} else {
			source.bounds.start = start + page.offsets[i]*period
			source.bounds.end = min(source.bounds.end, source.bounds.start+allocated[i]*period)
		}
		source.series.partial = allocated[i] < remaining[i]
		page.more = page.more || source.series.partial
		page.offsets[i] += allocated[i]
		if w := source.read(r, readBuckets); w != nil {
			return w
		}
	}
	return nil
}

func (source *metricReadSource) read(r Reader, readBuckets metricBucketReader) *awswire.Error {
	source.series.window = &source.bounds
	if !source.bounds.available || source.metricID == "" || source.bounds.start >= source.bounds.end {
		return nil
	}
	buckets, w := readBuckets(r, source.metricID, source.bounds.start, source.bounds.end, source.metric.period, source.unit, !basicStatistic(source.metric.statistic.name))
	if w != nil {
		return w
	}
	units := map[string]struct{}{}
	for i, bucket := range buckets {
		units[bucket.unit] = struct{}{}
		if i > 0 && buckets[i-1].at == bucket.at {
			continue
		}
		value, present, w := bucket.statistic(source.metric.statistic)
		if w != nil {
			return w
		}
		if present {
			source.series.values[bucket.at] = value
		}
	}
	if len(units) > 1 {
		ordered := make([]string, 0, len(units))
		for unit := range units {
			ordered = append(ordered, unit)
		}
		slices.Sort(ordered)
		source.messages = api.MetricDataResultMessages{dataMessage("MultipleUnits", "Multiple units returned: '["+strings.Join(ordered, ", ")+"]'")}
	}
	return nil
}
