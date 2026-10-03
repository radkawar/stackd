package kinesis

import (
	domain "stackd/storage/kinesis"
	"stackd/storage/sqlite/kinesis/internal/sqlcgen"
)

func (r reader) NextMetricPublication() (domain.MetricPublicationKey, error) {
	v, err := r.q.NextMetricPublication(r.ctx)
	if err != nil {
		return domain.MetricPublicationKey{}, missing(err)
	}
	return domain.MetricPublicationKey{Stream: domain.StreamKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, Minute: v.Minute.UTC()}, nil
}
func (r reader) MetricSamples(key domain.MetricPublicationKey) ([]domain.MetricSample, error) {
	k := key.Stream
	rows, err := r.q.ListMetricSamples(r.ctx, sqlcgen.ListMetricSamplesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Minute: key.Minute.UTC()})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MetricSample, len(rows))
	for i, v := range rows {
		out[i] = domain.MetricSample{ConsumerName: v.ConsumerName, ShardID: v.ShardID, Name: v.MetricName, Value: v.Value, SampleCount: v.SampleCount}
	}
	return out, nil
}
func (w writer) AddMetricSamples(key domain.MetricPublicationKey, samples []domain.MetricSample) error {
	k := key.Stream
	for _, v := range samples {
		if err := w.q.AddMetricSample(w.ctx, sqlcgen.AddMetricSampleParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Minute: key.Minute.UTC(), ConsumerName: v.ConsumerName, ShardID: v.ShardID, MetricName: v.Name, Value: v.Value, SampleCount: v.SampleCount}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteMetricPublication(key domain.MetricPublicationKey) error {
	k := key.Stream
	return w.q.DeleteMetricSamples(w.ctx, sqlcgen.DeleteMetricSamplesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Minute: key.Minute.UTC()})
}
