package elbv2

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/elbv2"
	"stackd/storage/sqlite/elbv2/internal/sqlcgen"
)

func (r reader) NextMetricPublication() (domain.MetricPublicationKey, bool, error) {
	row, err := r.q.NextMetricPublication(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.MetricPublicationKey{}, false, nil
	}
	return domain.MetricPublicationKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, LoadBalancerARN: row.LoadBalancerArn, Due: readTime(row.Due)}, err == nil, err
}

func (r reader) MetricSamples(key domain.MetricPublicationKey) ([]domain.MetricSample, error) {
	rows, err := r.q.ListMetricSamples(r.ctx, sqlcgen.ListMetricSamplesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, LoadBalancerArn: key.LoadBalancerARN, Due: timeValue(key.Due)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MetricSample, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.MetricSample{Name: row.Name, TargetGroupARN: row.TargetGroupArn, AvailabilityZone: row.AvailabilityZone, Minimum: row.Minimum, Maximum: row.Maximum, Sum: row.Sum, Count: row.Count})
	}
	return out, nil
}

func (w writer) AddMetricSamples(key domain.MetricPublicationKey, samples []domain.MetricSample) error {
	for _, sample := range samples {
		if err := w.q.AddMetricSample(w.ctx, sqlcgen.AddMetricSampleParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, LoadBalancerArn: key.LoadBalancerARN, Due: timeValue(key.Due), Name: sample.Name, TargetGroupArn: sample.TargetGroupARN, AvailabilityZone: sample.AvailabilityZone, Minimum: sample.Minimum, Maximum: sample.Maximum, Sum: sample.Sum, Count: sample.Count}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteMetricPublication(key domain.MetricPublicationKey) error {
	return w.q.DeleteMetricPublication(w.ctx, sqlcgen.DeleteMetricPublicationParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, LoadBalancerArn: key.LoadBalancerARN, Due: timeValue(key.Due)})
}

func (w writer) SetNextMetricAt(scope domain.Scope, arn string, at time.Time) error {
	return w.q.SetNextMetricAt(w.ctx, sqlcgen.SetNextMetricAtParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Arn: arn, NextMetricAt: timeValue(at)})
}
