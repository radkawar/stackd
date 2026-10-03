package cloudwatch

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

type insightsGroupValue struct {
	value   string
	present bool
}

type insightsGroup struct {
	fields  []insightsGroupValue
	buckets map[int64]*metricBucket
	series  *mathSeries
	rank    float64
}

func (q *insightsQuery) usesTags() bool {
	for _, predicate := range q.predicates {
		if strings.HasPrefix(predicate.field, "tag.") {
			return true
		}
	}
	for _, field := range q.group {
		if strings.HasPrefix(field, "tag.") {
			return true
		}
	}
	return false
}

func insightsField(record MetricRecord, field string) (string, bool) {
	if field == "AWS.AccountId" {
		return record.Key.AccountID, true
	}
	if strings.HasPrefix(field, "tag.") {
		// Custom publications have no resource-tag association. Associated AWS
		// metrics are rejected by the query owner until that metadata is retained.
		return "", false
	}
	at, found := slices.BinarySearchFunc(record.Dimensions, field, func(d Dimension, name string) int { return cmp.Compare(d.Name, name) })
	if !found {
		return "", false
	}
	return record.Dimensions[at].Value, true
}

func (q *insightsQuery) matches(record MetricRecord) bool {
	if q.schema != nil {
		if len(q.schema) != len(record.Dimensions) {
			return false
		}
		for i, name := range q.schema {
			if record.Dimensions[i].Name != name {
				return false
			}
		}
	}
	for _, predicate := range q.predicates {
		actual, present := insightsField(record, predicate.field)
		expected := predicate.value
		if predicate.currentAccount {
			expected = record.Key.AccountID
		}
		equal := present && actual == expected
		if equal == predicate.notEqual {
			return false
		}
	}
	return true
}

func evaluateInsights(r Reader, scope Scope, query *insightsQuery, now time.Time, period int64, bounds metricQueryBounds, readBuckets metricBucketReader) (evaluatedQuery, *awswire.Error) {
	out := evaluatedQuery{status: "Complete", value: mathValue{array: len(query.group) > 0, series: []*mathSeries{}}}
	if !out.value.array {
		out.value.series = append(out.value.series, &mathSeries{period: period, window: &bounds, values: map[int64]float64{}})
	}
	if !bounds.available {
		return out, nil
	}
	oldest := now.Add(-14 * 24 * time.Hour).Unix()
	if bounds.start < oldest {
		out.topMessages = api.MetricDataResultMessages{dataMessage("MaxQueryTimeRangeExceeded", "Max time window exceeded for query")}
		bounds.start = floorTime(oldest, 60)
	}
	if bounds.end < oldest {
		out.status = "InternalError"
		out.messages = api.MetricDataResultMessages{dataMessage("InternalError", "An unexpected error occurred during the evaluation of the expression")}
		out.value = mathValue{series: []*mathSeries{{period: period, values: map[int64]float64{}}}}
		return out, nil
	}
	if bounds.end <= bounds.start {
		return out, nil
	}
	groups := map[string]*insightsGroup{}
	if !out.value.array {
		groups[""] = &insightsGroup{buckets: map[int64]*metricBucket{}, series: out.value.series[0]}
	}
	selection := MetricQuery{Scope: scope, Namespace: query.namespace, Name: query.metric, PublishedAfter: now.Add(-14 * 24 * time.Hour), Limit: 500}
	fields := make([]insightsGroupValue, len(query.group))
	var key []byte
	matched := 0
	for matched < 10000 {
		records, err := r.Metrics(selection)
		if err != nil {
			return out, wireError(err)
		}
		for _, record := range records {
			if !query.matches(record) {
				continue
			}
			matched++
			buckets, w := readBuckets(r, record.ID, bounds.start, bounds.end, period, "", false)
			if w != nil {
				return out, w
			}
			if len(buckets) > 0 {
				key = key[:0]
				for i, field := range query.group {
					fields[i].value, fields[i].present = insightsField(record, field)
					if fields[i].present {
						key = strconv.AppendQuote(append(key, 1), fields[i].value)
					} else {
						key = append(key, 0)
					}
				}
				group := groups[string(key)]
				if group == nil {
					group = &insightsGroup{fields: slices.Clone(fields), buckets: map[int64]*metricBucket{}, series: &mathSeries{period: period, window: &bounds, values: map[int64]float64{}}}
					groups[string(key)] = group
				}
				for _, bucket := range buckets {
					combined := group.buckets[bucket.at]
					if combined == nil {
						combined = &metricBucket{at: bucket.at}
						group.buckets[bucket.at] = combined
					}
					combined.addSummary(bucket.count, bucket.sum, bucket.min, bucket.max)
				}
			}
			if matched == 10000 {
				break
			}
		}
		if len(records) < selection.Limit {
			break
		}
		selection.After = &records[len(records)-1].Key
	}
	ordered := make([]*insightsGroup, 0, len(groups))
	for _, group := range groups {
		for at, bucket := range group.buckets {
			v, present, w := bucket.statistic(query.statistic)
			if w != nil {
				return out, w
			}
			if present {
				group.series.values[at] = v
			}
		}
		if query.order != "" {
			values := make([]float64, 0, len(group.series.values))
			for _, at := range seriesTimes(group.series) {
				values = append(values, group.series.values[at])
			}
			switch query.order {
			case "SampleCount":
				group.rank = float64(len(values))
			case "Average":
				group.rank = mathReduce("AVG", values, len(values))
			case "Minimum":
				group.rank = mathReduce("MIN", values, len(values))
			case "Maximum":
				group.rank = mathReduce("MAX", values, len(values))
			case "Sum":
				group.rank = mathReduce("SUM", values, len(values))
			}
		}
		ordered = append(ordered, group)
	}
	slices.SortFunc(ordered, func(a, b *insightsGroup) int {
		if query.order != "" {
			order := cmp.Compare(a.rank, b.rank)
			if order != 0 {
				if query.descending {
					return -order
				}
				return order
			}
		}
		for i, field := range a.fields {
			other := b.fields[i]
			if field.present != other.present {
				if field.present {
					return -1
				}
				return 1
			}
			if order := cmp.Compare(field.value, other.value); order != 0 {
				return order
			}
		}
		return 0
	})
	out.value.series = out.value.series[:0]
	for i, group := range ordered[:min(len(ordered), query.limit)] {
		group.series.group = group.fields
		labels := make([]string, len(group.fields))
		for j, field := range group.fields {
			labels[j] = field.value
			if !field.present {
				labels[j] = "Other"
			}
		}
		group.series.label = strings.Join(labels, " ")
		if query.order != "" && out.value.array {
			group.series.label = fmt.Sprintf("%d - %s", i+1, group.series.label)
		}
		out.value.series = append(out.value.series, group.series)
	}
	return out, nil
}
