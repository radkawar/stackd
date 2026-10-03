package dynamodb

import (
	"cmp"
	"maps"
	"slices"

	api "stackd/internal/awsapi/dynamodb"
)

type metricSampleKey struct {
	index         string
	operation     string
	operationType string
	verb          string
	name          string
	value         float64
}

func cloneMetricSamples(rows map[MetricPublicationKey]map[metricSampleKey]int64) map[MetricPublicationKey]map[metricSampleKey]int64 {
	out := maps.Clone(rows)
	for key, group := range out {
		out[key] = maps.Clone(group)
	}
	return out
}

func compareMetricPublicationKeys(a, b MetricPublicationKey) int {
	return cmp.Or(a.Minute.Compare(b.Minute),
		cmp.Compare(a.Table.Partition, b.Table.Partition),
		cmp.Compare(a.Table.AccountID, b.Table.AccountID),
		cmp.Compare(a.Table.Region, b.Table.Region),
		cmp.Compare(a.Table.Name, b.Table.Name))
}

func (r memoryReader) NextMetricPublication() (MetricPublicationKey, error) {
	if err := r.tx.Check(false); err != nil {
		return MetricPublicationKey{}, err
	}
	var key MetricPublicationKey
	found := false
	for candidate := range r.s.metrics {
		if !found || compareMetricPublicationKeys(candidate, key) < 0 {
			key, found = candidate, true
		}
	}
	if !found {
		return MetricPublicationKey{}, ErrNotFound
	}
	return key, nil
}

func (r memoryReader) MetricSamples(key MetricPublicationKey) ([]MetricSample, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	group := r.s.metrics[key]
	out := make([]MetricSample, 0, len(group))
	for sample, count := range group {
		out = append(out, MetricSample{IndexName: sample.index, Operation: sample.operation, OperationType: sample.operationType, Verb: sample.verb, Name: sample.name, Value: sample.value, SampleCount: count})
	}
	slices.SortFunc(out, func(a, b MetricSample) int {
		return cmp.Or(cmp.Compare(a.IndexName, b.IndexName), cmp.Compare(a.Operation, b.Operation), cmp.Compare(a.OperationType, b.OperationType), cmp.Compare(a.Verb, b.Verb), cmp.Compare(a.Name, b.Name), cmp.Compare(a.Value, b.Value))
	})
	return out, nil
}

func (w memoryWriter) AddMetricSamples(key MetricPublicationKey, samples []MetricSample) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if len(samples) == 0 {
		return nil
	}
	group := w.s.metrics[key]
	if group == nil {
		group = make(map[metricSampleKey]int64, len(samples))
		w.s.metrics[key] = group
	}
	for _, sample := range samples {
		group[metricSampleKey{index: sample.IndexName, operation: sample.Operation, operationType: sample.OperationType, verb: sample.Verb, name: sample.Name, value: sample.Value}] += sample.SampleCount
	}
	return nil
}

func (w memoryWriter) DeleteMetricPublication(key MetricPublicationKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.metrics, key)
	return nil
}

func (r memoryReader) NextMetricTable() (TableRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TableRecord{}, err
	}
	var next TableRecord
	found := false
	for _, table := range r.s.tables {
		if table.Data.TableStatus == nil || (*table.Data.TableStatus != api.TableStatusACTIVE && *table.Data.TableStatus != api.TableStatusUPDATING) {
			continue
		}
		if !found || cmp.Or(table.MetricsNextAt.Compare(next.MetricsNextAt), compareTables(table, next)) < 0 {
			next, found = table, true
		}
	}
	if !found {
		return TableRecord{}, ErrNotFound
	}
	return cloneTableRecord(next), nil
}
