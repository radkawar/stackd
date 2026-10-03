package apigateway

import (
	"cmp"
	"maps"
	"slices"
)

type metricSampleKey struct {
	name  string
	value float64
}

func compareMetricKeys(a, b MetricPublicationKey) int {
	return cmp.Or(a.Minute.Compare(b.Minute),
		cmp.Compare(a.API.Partition, b.API.Partition), cmp.Compare(a.API.AccountID, b.API.AccountID),
		cmp.Compare(a.API.Region, b.API.Region), cmp.Compare(a.API.ID, b.API.ID),
		cmp.Compare(a.ProtocolType, b.ProtocolType), cmp.Compare(a.APIName, b.APIName),
		cmp.Compare(a.Stage, b.Stage), cmp.Compare(a.Method, b.Method),
		cmp.Compare(a.Resource, b.Resource), cmp.Compare(a.Route, b.Route))
}

func (r memoryReader) NextMetricPublication() (MetricPublicationKey, error) {
	if err := r.tx.Check(false); err != nil {
		return MetricPublicationKey{}, err
	}
	var selected MetricPublicationKey
	found := false
	for key := range r.s.metricSamples {
		if !found || compareMetricKeys(key, selected) < 0 {
			selected, found = key, true
		}
	}
	if !found {
		return MetricPublicationKey{}, ErrNotFound
	}
	return selected, nil
}

func (r memoryReader) MetricSamples(key MetricPublicationKey) ([]MetricSample, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	group := r.s.metricSamples[key]
	out := make([]MetricSample, 0, len(group))
	for sample, count := range group {
		out = append(out, MetricSample{Name: sample.name, Value: sample.value, SampleCount: count})
	}
	slices.SortFunc(out, func(a, b MetricSample) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Value, b.Value))
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
	group := maps.Clone(w.s.metricSamples[key])
	if group == nil {
		group = make(map[metricSampleKey]int64, len(samples))
	}
	for _, sample := range samples {
		group[metricSampleKey{sample.Name, sample.Value}] += sample.SampleCount
	}
	w.s.metricSamples[key] = group
	return nil
}

func (w memoryWriter) DeleteMetricPublication(key MetricPublicationKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.metricSamples, key)
	return nil
}
