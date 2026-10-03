package dynamodb

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
)

type dataMetricsKey struct{}
type dataMetrics struct {
	samples       map[MetricPublicationKey][]MetricSample
	operationType string
	verb          string
}

func (s *Service) withDataMetrics(ctx context.Context) context.Context {
	if s.metrics == nil {
		return ctx
	}
	return context.WithValue(ctx, dataMetricsKey{}, &dataMetrics{samples: make(map[MetricPublicationKey][]MetricSample)})
}

func observePartiQLMetricOperation(ctx context.Context, operationType, verb string) {
	if observed, _ := ctx.Value(dataMetricsKey{}).(*dataMetrics); observed != nil {
		observed.operationType, observed.verb = operationType, verb
	}
}

func (s *Service) completeExternal(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	observed, _ := ctx.Value(dataMetricsKey{}).(*dataMetrics)
	if observed == nil || len(observed.samples) == 0 {
		return s.recordCall(ctx, action, in, out, rejected)
	}
	if rejected != nil && capacityThrottled(rejected) {
		for key, samples := range observed.samples {
			for _, sample := range samples {
				if sample.Name == metricReadThrottle || sample.Name == metricWriteThrottle {
					observed.samples[key] = append(samples, MetricSample{Name: metricThrottledRequests, Operation: action, OperationType: observed.operationType, Verb: observed.verb, Value: 1, SampleCount: 1})
					break
				}
			}
		}
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		for key, samples := range observed.samples {
			if err := tx.AddMetricSamples(key, samples); err != nil {
				return err
			}
		}
		return s.recordCall(tx.Context(), action, in, out, rejected)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return err
}

func (s *Service) capacityRequest(requested *api.ReturnConsumedCapacity, table *TableRecord, additional ...*TableRecord) *api.ReturnConsumedCapacity {
	if !s.needsCapacity(requested, false, table, additional...) {
		return requested
	}
	// Generated request binding owns enum validation. The private engine input
	// requests components even when the public response must omit capacity.
	return new(api.ReturnConsumedCapacityINDEXES)
}

func (s *Service) completeCapacity(ctx context.Context, table *TableRecord, capacity **api.ConsumedCapacity, requested *api.ReturnConsumedCapacity, write bool) error {
	dataCapacity(*capacity, table)
	if s.metrics != nil {
		if *capacity == nil || (*capacity).Table == nil {
			return errors.New("DynamoDB engine omitted requested capacity components")
		}
		s.observeCapacity(ctx, table.Key, *capacity, write)
	}
	*capacity = capacityResponse(*capacity, requested)
	return nil
}

func capacityResponse(capacity *api.ConsumedCapacity, requested *api.ReturnConsumedCapacity) *api.ConsumedCapacity {
	if capacity == nil {
		return nil
	}
	switch value(requested) {
	case "", "NONE":
		return nil
	case "TOTAL":
		capacity.Table = nil
		capacity.LocalSecondaryIndexes = nil
		capacity.GlobalSecondaryIndexes = nil
	}
	return capacity
}

func (s *Service) completeCapacities(ctx context.Context, plan *dataPlan, capacities *api.ConsumedCapacityMultiple, requested *api.ReturnConsumedCapacity, write bool) error {
	plan.capacities(*capacities)
	for i := range *capacities {
		capacity := &(*capacities)[i]
		if s.metrics != nil {
			if capacity.Table == nil {
				return errors.New("DynamoDB engine omitted requested capacity components")
			}
			s.observeCapacity(ctx, TableKey{Scope: plan.table.Key.Scope, Name: value(capacity.TableName)}, capacity, write)
		}
		capacityResponse(capacity, requested)
	}
	if value(requested) == "" || value(requested) == "NONE" {
		*capacities = nil
	}
	return nil
}

type consumedUnits struct{ read, write float64 }

func capacityUnits(capacity *api.Capacity, write bool) consumedUnits {
	var units consumedUnits
	if capacity.ReadCapacityUnits != nil || capacity.WriteCapacityUnits != nil {
		if capacity.ReadCapacityUnits != nil {
			units.read = float64(*capacity.ReadCapacityUnits)
		}
		if capacity.WriteCapacityUnits != nil {
			units.write = float64(*capacity.WriteCapacityUnits)
		}
	} else if capacity.CapacityUnits != nil {
		if write {
			units.write = float64(*capacity.CapacityUnits)
		} else {
			units.read = float64(*capacity.CapacityUnits)
		}
	}
	return units
}

func (s *Service) observeCapacity(ctx context.Context, table TableKey, capacity *api.ConsumedCapacity, write bool) {
	observed, _ := ctx.Value(dataMetricsKey{}).(*dataMetrics)
	if observed == nil {
		return
	}
	key := MetricPublicationKey{Table: table, Minute: s.clock.Now().UTC().Truncate(time.Minute)}
	units := tableCapacityUnits(capacity, write)
	observed.samples[key] = appendCapacitySamples(observed.samples[key], "", units)
	for name, index := range capacity.GlobalSecondaryIndexes {
		observed.samples[key] = appendCapacitySamples(observed.samples[key], string(name), capacityUnits(&index, write))
	}
}

func appendCapacitySamples(samples []MetricSample, index string, units consumedUnits) []MetricSample {
	if units.read != 0 {
		samples = append(samples, MetricSample{IndexName: index, Name: metricConsumedRead, Value: units.read, SampleCount: 1})
	}
	if units.write != 0 {
		samples = append(samples, MetricSample{IndexName: index, Name: metricConsumedWrite, Value: units.write, SampleCount: 1})
	}
	return samples
}

func tableMetricSamples(table *TableRecord, gauges bool) (consumed, throughput []MetricSample) {
	consumed = make([]MetricSample, 0, (len(table.Data.GlobalSecondaryIndexes)+1)*2)
	provisioned := provisionedTable(table)
	add := func(index string, capacity *api.ProvisionedThroughputDescription, onDemand *api.OnDemandThroughput) {
		consumed = append(consumed,
			MetricSample{IndexName: index, Name: metricConsumedRead, SampleCount: 1},
			MetricSample{IndexName: index, Name: metricConsumedWrite, SampleCount: 1})
		if !gauges {
			return
		}
		if !provisioned {
			if units := onDemandRate(onDemand, false); units > 0 {
				throughput = append(throughput, MetricSample{IndexName: index, Name: "OnDemandMaxReadRequestUnits", Value: units, SampleCount: 1})
			}
			if units := onDemandRate(onDemand, true); units > 0 {
				throughput = append(throughput, MetricSample{IndexName: index, Name: "OnDemandMaxWriteRequestUnits", Value: units, SampleCount: 1})
			}
		} else if capacity != nil {
			if capacity.ReadCapacityUnits != nil {
				throughput = append(throughput, MetricSample{IndexName: index, Name: "ProvisionedReadCapacityUnits", Value: float64(*capacity.ReadCapacityUnits), SampleCount: 1})
			}
			if capacity.WriteCapacityUnits != nil {
				throughput = append(throughput, MetricSample{IndexName: index, Name: "ProvisionedWriteCapacityUnits", Value: float64(*capacity.WriteCapacityUnits), SampleCount: 1})
			}
		}
	}
	add("", table.Data.ProvisionedThroughput, table.Data.OnDemandThroughput)
	for _, index := range table.Data.GlobalSecondaryIndexes {
		if status := value(index.IndexStatus); status != "ACTIVE" && status != "UPDATING" {
			continue
		}
		add(value(index.IndexName), index.ProvisionedThroughput, index.OnDemandThroughput)
	}
	return consumed, throughput
}
