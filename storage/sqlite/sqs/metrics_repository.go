package sqs

import (
	"database/sql"
	"errors"

	"stackd/storage/sqlite/sqs/internal/sqlcgen"
	domain "stackd/storage/sqs"
)

func (r reader) NextMetricPublication() (domain.MetricPublicationKey, error) {
	v, err := r.q.NextMetricPublication(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.MetricPublicationKey{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.MetricPublicationKey{}, err
	}
	return domain.MetricPublicationKey{
		Queue:  domain.QueueKey{Partition: v.Partition, Account: v.Account, Region: v.Region, Name: v.QueueName},
		Minute: v.Minute,
	}, nil
}

func (r reader) MetricSamples(k domain.MetricPublicationKey) ([]domain.MetricSample, error) {
	rows, err := r.q.GetMetricSamples(r.ctx, sqlcgen.GetMetricSamplesParams{
		Partition: k.Queue.Partition, Account: k.Queue.Account, Region: k.Queue.Region, QueueName: k.Queue.Name, Minute: k.Minute,
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
			Partition: k.Queue.Partition, Account: k.Queue.Account, Region: k.Queue.Region, QueueName: k.Queue.Name, Minute: k.Minute,
			MetricName: v.Name, Value: v.Value, SampleCount: v.SampleCount,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteMetricPublication(k domain.MetricPublicationKey) error {
	return w.q.DeleteMetricPublication(w.ctx, sqlcgen.DeleteMetricPublicationParams{
		Partition: k.Queue.Partition, Account: k.Queue.Account, Region: k.Queue.Region, QueueName: k.Queue.Name, Minute: k.Minute,
	})
}
