package dynamodb

import (
	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
)

func (r reader) NextMetricPublication() (domain.MetricPublicationKey, error) {
	v, err := r.q.NextMetricPublication(r.ctx)
	if err != nil {
		return domain.MetricPublicationKey{}, missing(err)
	}
	return domain.MetricPublicationKey{
		Table:  domain.TableKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.TableName},
		Minute: v.Minute,
	}, nil
}

func (r reader) MetricSamples(k domain.MetricPublicationKey) ([]domain.MetricSample, error) {
	rows, err := r.q.GetMetricSamples(r.ctx, sqlcgen.GetMetricSamplesParams{
		Partition: k.Table.Partition, AccountID: k.Table.AccountID, Region: k.Table.Region, TableName: k.Table.Name, Minute: k.Minute,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MetricSample, 0, len(rows))
	for _, v := range rows {
		out = append(out, domain.MetricSample{IndexName: v.IndexName, Operation: v.Operation, OperationType: v.OperationType, Verb: v.Verb, Name: v.MetricName, Value: v.Value, SampleCount: v.SampleCount})
	}
	return out, nil
}

func (w writer) AddMetricSamples(k domain.MetricPublicationKey, samples []domain.MetricSample) error {
	for _, v := range samples {
		if err := w.q.AddMetricSample(w.ctx, sqlcgen.AddMetricSampleParams{
			Partition: k.Table.Partition, AccountID: k.Table.AccountID, Region: k.Table.Region, TableName: k.Table.Name, Minute: k.Minute,
			IndexName: v.IndexName, Operation: v.Operation, OperationType: v.OperationType, Verb: v.Verb, MetricName: v.Name, Value: v.Value, SampleCount: v.SampleCount,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteMetricPublication(k domain.MetricPublicationKey) error {
	return w.q.DeleteMetricPublication(w.ctx, sqlcgen.DeleteMetricPublicationParams{
		Partition: k.Table.Partition, AccountID: k.Table.AccountID, Region: k.Table.Region, TableName: k.Table.Name, Minute: k.Minute,
	})
}

func (r reader) NextMetricTable() (domain.TableRecord, error) {
	row, err := r.q.NextMetricTable(r.ctx)
	if err != nil {
		return domain.TableRecord{}, missing(err)
	}
	return r.table(row)
}
