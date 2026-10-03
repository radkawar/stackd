package cloudwatch

import (
	"strconv"
	"strings"
)

// queryMetric owns the validated identity, statistic and period of a metric
// selected directly or discovered by SEARCH.
type queryMetric struct {
	key        MetricKey
	dimensions []Dimension
	statistic  statisticSpec
	period     int64
}

// automaticMetricLabels removes shared namespace and dimension context, then
// distinguishes statistics and periods of the same metric. Source preparation
// selects the participants; hidden SEARCH results still contribute context.
func automaticMetricLabels(sources []*metricReadSource) []string {
	type field struct {
		value     string
		present   int
		different bool
	}
	add := func(f field, value string) field {
		if f.present == 0 {
			f.value = value
		} else if f.value != value {
			f.different = true
		}
		f.present++
		return f
	}
	type metricFields struct{ stat, period field }
	labels := make([]string, len(sources))
	var namespace, name field
	dimensions := map[string]field{}
	metrics := map[MetricKey]metricFields{}
	count := len(sources)
	for i, source := range sources {
		metric := source.metric
		labels[i] = metric.key.Name
		namespace = add(namespace, metric.key.Namespace)
		name = add(name, metric.key.Name)
		for _, dimension := range metric.dimensions {
			dimensions[dimension.Name] = add(dimensions[dimension.Name], dimension.Value)
		}
		fields := metrics[metric.key]
		fields.stat = add(fields.stat, metric.statistic.name)
		fields.period = add(fields.period, strconv.FormatInt(metric.period, 10))
		metrics[metric.key] = fields
	}
	for i, source := range sources {
		metric := source.metric
		var parts []string
		if namespace.different {
			parts = append(parts, metric.key.Namespace)
		}
		for _, dimension := range metric.dimensions {
			field := dimensions[dimension.Name]
			if field.different || field.present != count {
				parts = append(parts, dimension.Value)
			}
		}
		if name.different || len(parts) == 0 {
			parts = append(parts, metric.key.Name)
		}
		fields := metrics[metric.key]
		if fields.stat.different {
			parts = append(parts, metric.statistic.name)
		}
		if fields.period.different {
			parts = append(parts, strconv.FormatInt(metric.period, 10))
		}
		labels[i] = strings.Join(parts, " ")
	}
	return labels
}
