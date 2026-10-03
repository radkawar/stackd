package elbv2

import (
	"cmp"
	"slices"
	"time"
)

type metricSampleKey struct{ name, group, zone string }

func (r memoryReader) NextMetricPublication() (MetricPublicationKey, bool, error) {
	if err := r.t.Check(false); err != nil {
		return MetricPublicationKey{}, false, err
	}
	var next MetricPublicationKey
	found := false
	for key := range r.s.metricSamples {
		if !found || key.Due.Before(next.Due) || key.Due.Equal(next.Due) && key.LoadBalancerARN < next.LoadBalancerARN {
			next, found = key, true
		}
	}
	return next, found, nil
}

func (r memoryReader) MetricSamples(key MetricPublicationKey) ([]MetricSample, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := make([]MetricSample, 0, len(r.s.metricSamples[key]))
	for _, sample := range r.s.metricSamples[key] {
		out = append(out, sample)
	}
	slices.SortFunc(out, func(a, b MetricSample) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.TargetGroupARN, b.TargetGroupARN), cmp.Compare(a.AvailabilityZone, b.AvailabilityZone))
	})
	return out, nil
}

func (w memoryWriter) AddMetricSamples(key MetricPublicationKey, samples []MetricSample) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	if w.s.metricSamples[key] == nil {
		w.s.metricSamples[key] = map[metricSampleKey]MetricSample{}
	}
	for _, sample := range samples {
		k := metricSampleKey{sample.Name, sample.TargetGroupARN, sample.AvailabilityZone}
		if prior, found := w.s.metricSamples[key][k]; found {
			sample.Minimum = min(prior.Minimum, sample.Minimum)
			sample.Maximum = max(prior.Maximum, sample.Maximum)
			sample.Sum += prior.Sum
			sample.Count += prior.Count
		}
		w.s.metricSamples[key][k] = sample
	}
	return nil
}

func (w memoryWriter) DeleteMetricPublication(key MetricPublicationKey) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.metricSamples, key)
	return nil
}

func (w memoryWriter) SetNextMetricAt(scope Scope, arn string, at time.Time) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	key := recordKey{scope, arn}
	lb, found := w.s.loadBalancers[key]
	if !found {
		return ErrNotFound
	}
	lb.NextMetricAt = at
	w.s.loadBalancers[key] = lb
	return nil
}
