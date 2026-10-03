package apigateway

import (
	domain "stackd/internal/services/apigateway"
	"stackd/storage/sqlite/apigateway/internal/sqlcgen"
)

func (r reader) NextMetricPublication() (domain.MetricPublicationKey, error) {
	row, err := r.q.NextMetricPublication(r.ctx)
	if err != nil {
		return domain.MetricPublicationKey{}, missing(err)
	}
	return domain.MetricPublicationKey{
		API: apiKey(row.Partition, row.AccountID, row.Region, row.ApiID), Minute: row.Minute.UTC(),
		ProtocolType: row.ProtocolType, APIName: row.ApiName, Stage: row.Stage,
		Method: row.Method, Resource: row.Resource, Route: row.Route,
	}, nil
}

func (r reader) MetricSamples(key domain.MetricPublicationKey) ([]domain.MetricSample, error) {
	rows, err := r.q.ListMetricSamples(r.ctx, sqlcgen.ListMetricSamplesParams{
		Partition: key.API.Partition, AccountID: key.API.AccountID, Region: key.API.Region, ApiID: key.API.ID, Minute: key.Minute,
		ProtocolType: key.ProtocolType, ApiName: key.APIName, Stage: key.Stage, Method: key.Method, Resource: key.Resource, Route: key.Route,
	})
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
		if err := w.q.PutMetricSample(w.ctx, sqlcgen.PutMetricSampleParams{
			Partition: key.API.Partition, AccountID: key.API.AccountID, Region: key.API.Region, ApiID: key.API.ID, Minute: key.Minute,
			ProtocolType: key.ProtocolType, ApiName: key.APIName, Stage: key.Stage, Method: key.Method, Resource: key.Resource, Route: key.Route,
			MetricName: sample.Name, Value: sample.Value, SampleCount: sample.SampleCount,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteMetricPublication(key domain.MetricPublicationKey) error {
	return w.q.DeleteMetricPublication(w.ctx, sqlcgen.DeleteMetricPublicationParams{
		Partition: key.API.Partition, AccountID: key.API.AccountID, Region: key.API.Region, ApiID: key.API.ID, Minute: key.Minute,
		ProtocolType: key.ProtocolType, ApiName: key.APIName, Stage: key.Stage, Method: key.Method, Resource: key.Resource, Route: key.Route,
	})
}
