package dynamodb

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
)

func (s *Service) admit(ctx context.Context, table *TableRecord, index string, write bool) error {
	blocked := s.admission.check(table, index, write)
	if len(blocked) == 0 {
		return nil
	}
	return s.throttle(ctx, table, blocked, write, 1)
}

func (s *Service) admitPlan(ctx context.Context, plan *dataPlan, write bool) error {
	if err := s.admit(ctx, plan.table, "", write); err != nil {
		return err
	}
	for _, table := range plan.additional {
		if err := s.admit(ctx, table, "", write); err != nil {
			return err
		}
	}
	return nil
}

// throttle records rejected resource events. Request-level counters are added at
// completion, so partial BatchGetItem/BatchWriteItem responses do not count as
// wholly throttled requests.
func (s *Service) throttle(ctx context.Context, table *TableRecord, blocked []api.IndexName, write bool, count int64) *awswire.Error {
	direction, metric := "Read", metricReadThrottle
	if write {
		direction, metric = "Write", metricWriteThrottle
	}
	code, field := "ProvisionedThroughputExceededException", "ThrottlingReasons"
	cause, metricCause := "ProvisionedThroughputExceeded", "ProvisionedThroughputThrottleEvents"
	message := "The level of configured provisioned throughput for the table or index was exceeded."
	if !provisionedTable(table) {
		cause, metricCause = "MaxOnDemandThroughputExceeded", "MaxOnDemandThroughputThrottleEvents"
		message = "The configured maximum throughput for the table or index was exceeded."
		// Individual writes use the provisioned exception for GSI backpressure
		// even in on-demand mode. Composite calls use ThrottlingException.
		request, _ := awsapi.FromContext(ctx)
		individual := request.Operation.Name == "PutItem" || request.Operation.Name == "UpdateItem" || request.Operation.Name == "DeleteItem" || request.Operation.Name == "ExecuteStatement"
		if !write || blocked[0] == "" || !individual {
			code, field = "ThrottlingException", "throttlingReasons"
		}
	}
	observed, _ := ctx.Value(dataMetricsKey{}).(*dataMetrics)
	key := MetricPublicationKey{Table: table.Key, Minute: s.clock.Now().UTC().Truncate(time.Minute)}
	reasons := make(api.ThrottlingReasonList, 0, len(blocked))
	for _, index := range blocked {
		resource, kind := table.Key.ARN(), "Table"
		if index != "" {
			resource += "/index/" + string(index)
			kind = "Index"
		}
		reasons = append(reasons, api.ThrottlingReason{Reason: new(api.Reason(kind + direction + cause)), Resource: new(api.Resource(resource))})
		if observed != nil {
			observed.samples[key] = append(observed.samples[key],
				MetricSample{IndexName: string(index), Name: metric, Value: 1, SampleCount: count},
				MetricSample{IndexName: string(index), Name: direction + metricCause, Value: 1, SampleCount: count})
		}
	}
	encoded, _ := json.Marshal(reasons) // Only generated string fields.
	rejected := failure(code, message)
	rejected.Details = map[string]json.RawMessage{field: encoded}
	return rejected
}

func capacityThrottled(err error) bool {
	var rejected *awswire.Error
	return errors.As(err, &rejected) && (rejected.Code == "ProvisionedThroughputExceededException" || rejected.Code == "ThrottlingException")
}

// readCapacity holds the same native data gate as writes. Admission and charging
// cannot race an admitted mutation or a batch's temporary budget projection.
func (s *Service) readCapacity(ctx context.Context, table *TableRecord, index, operation string, in, out any, capacity **api.ConsumedCapacity, requested *api.ReturnConsumedCapacity) error {
	return s.withData(ctx, table, func() error {
		if err := s.admit(ctx, table, index, false); err != nil {
			return err
		}
		if err := s.callEngine(ctx, table, operation, in, out); err != nil {
			return err
		}
		s.admission.charge(table, *capacity, false)
		return s.completeCapacity(ctx, table, capacity, requested, false)
	})
}

func tableCapacityUnits(capacity *api.ConsumedCapacity, write bool) consumedUnits {
	units := capacityUnits(capacity.Table, write)
	// LSIs share the base table budget; GSIs never enter this total.
	for _, index := range capacity.LocalSecondaryIndexes {
		part := capacityUnits(&index, write)
		units.read += part.read
		units.write += part.write
	}
	return units
}

func (a *capacityAdmission) charge(table *TableRecord, capacity *api.ConsumedCapacity, write bool) {
	if capacity == nil || capacity.Table == nil {
		return
	}
	a.consume(table, "", tableCapacityUnits(capacity, write))
	for name, index := range capacity.GlobalSecondaryIndexes {
		a.consume(table, string(name), capacityUnits(&index, write))
	}
}

// chargeCapacities consumes native physical names before response remapping.
func (s *Service) chargeCapacities(plan *dataPlan, capacities api.ConsumedCapacityMultiple, write bool) {
	for i := range capacities {
		capacity := &capacities[i]
		s.admission.charge(plan.tables[value(capacity.TableName)], capacity, write)
	}
}

func (s *Service) chargeReplay(plan *dataPlan, replay *TransactionCapacity) {
	for _, read := range replay.Read {
		for _, table := range plan.tables {
			if table.Key.Name == read.TableName {
				s.admission.consume(table, "", consumedUnits{read: read.Units})
				break
			}
		}
	}
}

func (plan *dataPlan) limited(write bool) bool {
	for _, table := range plan.tables {
		if capacityLimited(table, write) {
			return true
		}
	}
	return false
}
