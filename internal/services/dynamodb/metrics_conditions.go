package dynamodb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
)

func (s *Service) conditionCapacityRequest(requested *api.ReturnValuesOnConditionCheckFailure, table *TableRecord) *api.ReturnValuesOnConditionCheckFailure {
	if !s.needsCapacity(nil, true, table) {
		return requested
	}
	// The native atomic condition result supplies the evaluated preimage. A
	// separate GetItem would race the condition and require an extra round trip.
	return new(api.ReturnValuesOnConditionCheckFailureALL_OLD)
}

func (s *Service) conditionFailure(ctx context.Context, table *TableRecord, err error, requested *api.ReturnValuesOnConditionCheckFailure) error {
	var rejected *awswire.Error
	if !s.needsCapacity(nil, true, table) || !errors.As(err, &rejected) || rejected.Code != "ConditionalCheckFailedException" {
		return err
	}
	var item api.AttributeMap
	if raw := rejected.Details["Item"]; len(raw) != 0 {
		if decodeErr := json.Unmarshal(raw, &item); decodeErr != nil {
			return fmt.Errorf("decode DynamoDB conditional preimage: %w", decodeErr)
		}
	}
	s.observeWriteFailure(ctx, table, writeUnits(itemSize(item)), 1)
	if value(requested) != "ALL_OLD" {
		delete(rejected.Details, "Item")
	}
	return err
}

func (s *Service) observeWriteFailure(ctx context.Context, table *TableRecord, units, failures float64) {
	s.admission.consume(table, "", consumedUnits{write: units})
	observed, _ := ctx.Value(dataMetricsKey{}).(*dataMetrics)
	if observed == nil {
		return
	}
	key := MetricPublicationKey{Table: table.Key, Minute: s.clock.Now().UTC().Truncate(time.Minute)}
	if units != 0 {
		observed.samples[key] = append(observed.samples[key], MetricSample{Name: metricConsumedWrite, Value: units, SampleCount: 1})
	}
	if failures != 0 {
		observed.samples[key] = append(observed.samples[key], MetricSample{Name: metricConditionalFailures, Value: failures, SampleCount: 1})
	}
}
