package ecs

import (
	"cmp"
	"maps"
	"slices"
)

type metricSampleKey struct {
	name, taskID string
	resolution   int32
}

func (r memoryReader) NextMetricPublication() (MetricPublicationKey, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return MetricPublicationKey{}, false, err
	}
	var key MetricPublicationKey
	found := false
	for candidate := range r.s.metrics {
		if !found || cmp.Or(candidate.Due.Compare(key.Due), compareServiceKeys(candidate.ServiceKey, key.ServiceKey)) < 0 {
			key, found = candidate, true
		}
	}
	return key, found, nil
}

func (r memoryReader) MetricSamples(key MetricPublicationKey) ([]MetricSample, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]MetricSample, 0, len(r.s.metrics[key]))
	for _, sample := range r.s.metrics[key] {
		out = append(out, sample)
	}
	slices.SortFunc(out, func(a, b MetricSample) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.TaskID, b.TaskID), cmp.Compare(a.Resolution, b.Resolution))
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
	group := maps.Clone(w.s.metrics[key])
	if group == nil {
		group = make(map[metricSampleKey]MetricSample, len(samples))
	}
	for _, sample := range samples {
		id := metricSampleKey{sample.Name, sample.TaskID, sample.Resolution}
		if previous, exists := group[id]; exists {
			sample.Minimum = min(previous.Minimum, sample.Minimum)
			sample.Maximum = max(previous.Maximum, sample.Maximum)
			sample.Sum += previous.Sum
			sample.Count += previous.Count
		}
		group[id] = sample
	}
	w.s.metrics[key] = group
	return nil
}

func (w memoryWriter) DeleteMetricPublication(key MetricPublicationKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.metrics, key)
	return nil
}
