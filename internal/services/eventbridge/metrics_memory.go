package eventbridge

import (
	"cmp"
	"maps"
	"slices"
)

type metricSampleKey struct {
	name, eventBusName, ruleName, source string
	value                                float64
}

func compareMetricPublicationKeys(a, b MetricPublicationKey) int {
	return cmp.Or(a.Minute.Compare(b.Minute),
		cmp.Compare(a.Partition, b.Partition),
		cmp.Compare(a.Account, b.Account),
		cmp.Compare(a.Region, b.Region))
}

func (r memoryReader) NextMetricPublication() (MetricPublicationKey, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return MetricPublicationKey{}, false, err
	}
	var key MetricPublicationKey
	found := false
	for candidate := range r.s.metrics {
		if !found || compareMetricPublicationKeys(candidate, key) < 0 {
			key, found = candidate, true
		}
	}
	return key, found, nil
}

func (r memoryReader) MetricSamples(key MetricPublicationKey) ([]MetricSample, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	group := r.s.metrics[key]
	out := make([]MetricSample, 0, len(group))
	for sample, count := range group {
		out = append(out, MetricSample{Name: sample.name, EventBusName: sample.eventBusName, RuleName: sample.ruleName, Source: sample.source, Value: sample.value, SampleCount: count})
	}
	slices.SortFunc(out, func(a, b MetricSample) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.EventBusName, b.EventBusName),
			cmp.Compare(a.RuleName, b.RuleName),
			cmp.Compare(a.Source, b.Source),
			cmp.Compare(a.Value, b.Value))
	})
	return out, nil
}

func (w memoryWriter) AddMetricSamples(key MetricPublicationKey, samples []MetricSample) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if len(samples) == 0 {
		return nil
	}
	group := w.s.metrics[key]
	if group == nil {
		group = make(map[metricSampleKey]int64, len(samples))
		w.s.metrics[key] = group
	} else {
		group = maps.Clone(group)
		w.s.metrics[key] = group
	}
	for _, sample := range samples {
		group[metricSampleKey{name: sample.Name, eventBusName: sample.EventBusName, ruleName: sample.RuleName, source: sample.Source, value: sample.Value}] += sample.SampleCount
	}
	return nil
}

func (w memoryWriter) DeleteMetricPublication(key MetricPublicationKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.metrics, key)
	return nil
}
