package sqs

import (
	"cmp"
	"maps"
	"slices"
)

type metricSampleKey struct {
	name  string
	value int64
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
		cmp.Compare(a.Queue.Partition, b.Queue.Partition),
		cmp.Compare(a.Queue.Account, b.Queue.Account),
		cmp.Compare(a.Queue.Region, b.Queue.Region),
		cmp.Compare(a.Queue.Name, b.Queue.Name))
}

func (r memoryReader) NextMetricPublication() (MetricPublicationKey, error) {
	if err := r.tx.Check(false); err != nil {
		return MetricPublicationKey{}, err
	}
	var key MetricPublicationKey
	found := false
	for candidate := range r.state.metrics {
		if !found || compareMetricPublicationKeys(candidate, key) < 0 {
			key, found = candidate, true
		}
	}
	if !found {
		return MetricPublicationKey{}, ErrNotFound
	}
	return key, nil
}

func (r memoryReader) MetricSamples(key MetricPublicationKey) ([]MetricSample, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	group := r.state.metrics[key]
	out := make([]MetricSample, 0, len(group))
	for sample, count := range group {
		out = append(out, MetricSample{Name: sample.name, Value: sample.value, SampleCount: count})
	}
	slices.SortFunc(out, func(a, b MetricSample) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Value, b.Value))
	})
	return out, nil
}

func (t memoryTransaction) AddMetricSamples(key MetricPublicationKey, samples []MetricSample) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	if len(samples) == 0 {
		return nil
	}
	group := t.state.metrics[key]
	if group == nil {
		group = make(map[metricSampleKey]int64, len(samples))
		t.state.metrics[key] = group
	}
	for _, sample := range samples {
		group[metricSampleKey{name: sample.Name, value: sample.Value}] += sample.SampleCount
	}
	return nil
}

func (t memoryTransaction) DeleteMetricPublication(key MetricPublicationKey) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	delete(t.state.metrics, key)
	return nil
}

func (r memoryReader) NextMetricQueue() (QueueRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return QueueRecord{}, err
	}
	var next QueueRecord
	for _, queue := range r.state.queues {
		if queue.NextMetricSample.IsZero() {
			continue
		}
		key := MetricPublicationKey{Queue: queue.Key, Minute: queue.NextMetricSample}
		selected := MetricPublicationKey{Queue: next.Key, Minute: next.NextMetricSample}
		if next.NextMetricSample.IsZero() || compareMetricPublicationKeys(key, selected) < 0 {
			next = queue
		}
	}
	if next.NextMetricSample.IsZero() {
		return QueueRecord{}, ErrNotFound
	}
	return cloneQueueRecord(next), nil
}
