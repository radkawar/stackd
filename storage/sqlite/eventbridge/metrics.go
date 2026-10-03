package eventbridge

import (
	"database/sql"
	"errors"

	domain "stackd/storage/eventbridge"
	"stackd/storage/sqlite/eventbridge/internal/sqlcgen"
)

func (r reader) NextMetricPublication() (domain.MetricPublicationKey, bool, error) {
	v, err := r.q.NextMetricPublication(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.MetricPublicationKey{}, false, nil
	}
	if err != nil {
		return domain.MetricPublicationKey{}, false, err
	}
	return domain.MetricPublicationKey{
		Scope:  domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region},
		Minute: v.Minute,
	}, true, nil
}

func (r reader) MetricSamples(k domain.MetricPublicationKey) ([]domain.MetricSample, error) {
	rows, err := r.q.GetMetricSamples(r.ctx, sqlcgen.GetMetricSamplesParams{
		Partition: k.Partition, Account: k.Account, Region: k.Region, Minute: k.Minute,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MetricSample, 0, len(rows))
	for _, v := range rows {
		out = append(out, domain.MetricSample{Name: v.MetricName, EventBusName: v.EventBusName, RuleName: v.RuleName, Source: v.Source, Value: v.Value, SampleCount: v.SampleCount})
	}
	return out, nil
}

func (w writer) AddMetricSamples(k domain.MetricPublicationKey, samples []domain.MetricSample) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	for _, v := range samples {
		if err := w.q.AddMetricSample(w.ctx, sqlcgen.AddMetricSampleParams{
			Partition: k.Partition, Account: k.Account, Region: k.Region, Minute: k.Minute,
			MetricName: v.Name, EventBusName: v.EventBusName, RuleName: v.RuleName, Source: v.Source, Value: v.Value, SampleCount: v.SampleCount,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteMetricPublication(k domain.MetricPublicationKey) error {
	return w.q.DeleteMetricPublication(w.ctx, sqlcgen.DeleteMetricPublicationParams{
		Partition: k.Partition, Account: k.Account, Region: k.Region, Minute: k.Minute,
	})
}
