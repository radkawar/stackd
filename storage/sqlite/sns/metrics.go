package sns

import (
	domain "stackd/storage/sns"
	"stackd/storage/sqlite/sns/internal/sqlcgen"
)

func (r reader) NextMetricPublication() (domain.MetricPublicationKey, error) {
	v, err := r.q.NextMetricPublication(r.ctx)
	if err != nil {
		return domain.MetricPublicationKey{}, missing(err)
	}
	return domain.MetricPublicationKey{
		Topic:  domain.TopicKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.TopicName},
		Minute: v.Minute,
	}, nil
}

func (r reader) MetricSamples(k domain.MetricPublicationKey) ([]domain.MetricSample, error) {
	rows, err := r.q.GetMetricSamples(r.ctx, sqlcgen.GetMetricSamplesParams{
		Partition: k.Topic.Partition, AccountID: k.Topic.AccountID, Region: k.Topic.Region, TopicName: k.Topic.Name, Minute: k.Minute,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MetricSample, 0, len(rows))
	for _, v := range rows {
		out = append(out, domain.MetricSample{Name: v.MetricName, Value: v.Value, SampleCount: v.SampleCount})
	}
	return out, nil
}

func (w writer) AddMetricSamples(k domain.MetricPublicationKey, samples []domain.MetricSample) error {
	for _, v := range samples {
		if err := w.q.AddMetricSample(w.ctx, sqlcgen.AddMetricSampleParams{
			Partition: k.Topic.Partition, AccountID: k.Topic.AccountID, Region: k.Topic.Region, TopicName: k.Topic.Name, Minute: k.Minute,
			MetricName: v.Name, Value: v.Value, SampleCount: v.SampleCount,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteMetricPublication(k domain.MetricPublicationKey) error {
	return w.q.DeleteMetricPublication(w.ctx, sqlcgen.DeleteMetricPublicationParams{
		Partition: k.Topic.Partition, AccountID: k.Topic.AccountID, Region: k.Topic.Region, TopicName: k.Topic.Name, Minute: k.Minute,
	})
}
