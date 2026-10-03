package ecs

import (
	"database/sql"
	"errors"

	domain "stackd/storage/ecs"
	"stackd/storage/sqlite/ecs/internal/sqlcgen"
)

func (r reader) NextMetricPublication() (domain.MetricPublicationKey, bool, error) {
	row, err := r.q.NextMetricPublication(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.MetricPublicationKey{}, false, nil
	}
	if err != nil {
		return domain.MetricPublicationKey{}, false, err
	}
	return domain.MetricPublicationKey{
		ServiceKey: domain.ServiceKey{ClusterKey: domain.ClusterKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.ClusterName}, ServiceName: row.ServiceName},
		Due:        row.Due,
	}, true, nil
}

func (r reader) MetricSamples(key domain.MetricPublicationKey) ([]domain.MetricSample, error) {
	rows, err := r.q.MetricSamples(r.ctx, sqlcgen.MetricSamplesParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClusterName: key.Name, ServiceName: key.ServiceName, Due: key.Due,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MetricSample, len(rows))
	for i, row := range rows {
		out[i] = domain.MetricSample{Name: row.MetricName, TaskID: row.TaskID, Resolution: int32(row.ResolutionSeconds), Minimum: row.Minimum, Maximum: row.Maximum, Sum: row.ObservationSum, Count: row.ObservationCount}
	}
	return out, nil
}

func (w writer) AddMetricSamples(key domain.MetricPublicationKey, samples []domain.MetricSample) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	for _, sample := range samples {
		if err := w.q.AddMetricSample(w.ctx, sqlcgen.AddMetricSampleParams{
			Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClusterName: key.Name, ServiceName: key.ServiceName, Due: key.Due,
			MetricName: sample.Name, TaskID: sample.TaskID, ResolutionSeconds: int64(sample.Resolution),
			Minimum: sample.Minimum, Maximum: sample.Maximum, ObservationSum: sample.Sum, ObservationCount: sample.Count,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteMetricPublication(key domain.MetricPublicationKey) error {
	return w.q.DeleteMetricPublication(w.ctx, sqlcgen.DeleteMetricPublicationParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClusterName: key.Name, ServiceName: key.ServiceName, Due: key.Due,
	})
}
