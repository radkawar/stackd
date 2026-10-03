package firehose

import (
	domain "stackd/storage/firehose"
	"stackd/storage/sqlite/firehose/internal/sqlcgen"
)

func (r reader) NextMetricPublication() (domain.MetricPublicationKey, error) {
	v, err := r.q.NextMetricPublication(r.ctx)
	if err != nil {
		return domain.MetricPublicationKey{}, missing(err)
	}
	return domain.MetricPublicationKey{Stream: domain.StreamKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, Minute: v.Minute.UTC()}, nil
}

func (r reader) MetricSamples(key domain.MetricPublicationKey) ([]domain.MetricSample, error) {
	rows, err := r.q.ListMetricSamples(r.ctx, sqlcgen.ListMetricSamplesParams{Partition: key.Stream.Partition, AccountID: key.Stream.AccountID, Region: key.Stream.Region, Name: key.Stream.Name, Minute: key.Minute.UTC()})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MetricSample, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.MetricSample{Name: row.MetricName, Value: row.Value, SampleCount: row.SampleCount})
	}
	return out, nil
}

func (w writer) AddMetricSamples(key domain.MetricPublicationKey, samples []domain.MetricSample) error {
	for _, sample := range samples {
		if err := w.q.PutMetricSample(w.ctx, sqlcgen.PutMetricSampleParams{Partition: key.Stream.Partition, AccountID: key.Stream.AccountID, Region: key.Stream.Region, Name: key.Stream.Name, Minute: key.Minute.UTC(), MetricName: sample.Name, Value: sample.Value, SampleCount: sample.SampleCount}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteMetricPublication(key domain.MetricPublicationKey) error {
	return w.q.DeleteMetricPublication(w.ctx, sqlcgen.DeleteMetricPublicationParams{Partition: key.Stream.Partition, AccountID: key.Stream.AccountID, Region: key.Stream.Region, Name: key.Stream.Name, Minute: key.Minute.UTC()})
}
