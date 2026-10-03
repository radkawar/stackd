package lambda

import (
	"cmp"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type metricSampleKey struct {
	name  string
	value float64
}

func cloneMetricSamples(rows map[MetricPublicationKey]map[metricSampleKey]int64) map[MetricPublicationKey]map[metricSampleKey]int64 {
	out := maps.Clone(rows)
	for key, group := range out {
		out[key] = maps.Clone(group)
	}
	return out
}

func compareMetricPublicationKeys(a, b MetricPublicationKey) int {
	return cmp.Or(a.Minute.Compare(b.Minute),
		cmp.Compare(a.Function.Partition, b.Function.Partition),
		cmp.Compare(a.Function.Account, b.Function.Account),
		cmp.Compare(a.Function.Region, b.Function.Region),
		cmp.Compare(a.Function.Name, b.Function.Name),
		cmp.Compare(a.Resource, b.Resource),
		cmp.Compare(a.ExecutedVersion, b.ExecutedVersion),
		cmp.Compare(a.EventSourceMappingUUID, b.EventSourceMappingUUID))
}

func (r memoryReader) NextMetricPublication() (key MetricPublicationKey, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.metrics.View(r.Context(), func(rows *map[MetricPublicationKey]map[metricSampleKey]int64, _ *memory.Transaction) error {
		found := false
		for candidate := range *rows {
			if !found || compareMetricPublicationKeys(candidate, key) < 0 {
				key, found = candidate, true
			}
		}
		if !found {
			return ErrNotFound
		}
		return nil
	})
	return
}

func (r memoryReader) MetricSamples(key MetricPublicationKey) (out []MetricSample, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.metrics.View(r.Context(), func(rows *map[MetricPublicationKey]map[metricSampleKey]int64, _ *memory.Transaction) error {
		group := (*rows)[key]
		out = make([]MetricSample, 0, len(group))
		for sample, count := range group {
			out = append(out, MetricSample{Name: sample.name, Value: sample.value, SampleCount: count})
		}
		slices.SortFunc(out, func(a, b MetricSample) int {
			return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Value, b.Value))
		})
		return nil
	})
	return
}

func (w memoryWriter) AddMetricSamples(key MetricPublicationKey, samples []MetricSample) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if len(samples) == 0 {
		return nil
	}
	return w.repository.metrics.Update(w.Context(), func(rows *map[MetricPublicationKey]map[metricSampleKey]int64, _ *memory.Transaction) error {
		group := (*rows)[key]
		if group == nil {
			group = make(map[metricSampleKey]int64, len(samples))
			(*rows)[key] = group
		}
		for _, sample := range samples {
			group[metricSampleKey{name: sample.Name, value: sample.Value}] += sample.SampleCount
		}
		return nil
	})
}

func (w memoryWriter) DeleteMetricPublication(key MetricPublicationKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.metrics.Update(w.Context(), func(rows *map[MetricPublicationKey]map[metricSampleKey]int64, _ *memory.Transaction) error {
		delete(*rows, key)
		return nil
	})
}
