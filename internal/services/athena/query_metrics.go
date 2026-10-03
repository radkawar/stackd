package athena

import (
	"context"
	"log/slog"

	api "stackd/internal/awsapi/athena"
	metricsapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
)

// publishQueryMetrics enters the ordinary CloudWatch command in the owning
// query transaction. Names and dimensions follow the public Athena contract:
// https://docs.aws.amazon.com/athena/latest/ug/query-metrics-viewing.html
func (s *Service) publishQueryMetrics(ctx context.Context, v QueryRecord) error {
	state := queryState(v)
	if s.metrics == nil || !v.PublishMetrics || v.Data.Statistics == nil || value(v.Data.StatementType) == "" {
		return nil
	}
	if state != "SUCCEEDED" && state != "FAILED" && state != "CANCELLED" {
		return nil
	}
	if state == "CANCELLED" {
		state = "CANCELED"
	}
	dimensions := metricsapi.Dimensions{
		{Name: new(metricsapi.DimensionName("WorkGroup")), Value: new(metricsapi.DimensionValue(value(v.Data.WorkGroup)))},
		{Name: new(metricsapi.DimensionName("QueryType")), Value: new(metricsapi.DimensionValue(value(v.Data.StatementType)))},
		{Name: new(metricsapi.DimensionName("QueryState")), Value: new(metricsapi.DimensionValue(state))},
	}
	stats := v.Data.Statistics
	samples := make(metricsapi.MetricData, 0, 7)
	add := func(name string, val *api.Long, unit string) {
		if val == nil {
			return
		}
		samples = append(samples, metricsapi.MetricDatum{MetricName: new(metricsapi.MetricName(name)), Dimensions: dimensions, Timestamp: v.Data.Status.CompletionDateTime, Unit: new(metricsapi.StandardUnit(unit)), Value: new(metricsapi.DatapointValue(float64(*val)))})
	}
	if value(v.Data.StatementType) == "DML" {
		add("ProcessedBytes", stats.DataScannedInBytes, "Bytes")
	}
	add("EngineExecutionTime", stats.EngineExecutionTimeInMillis, "Milliseconds")
	add("QueryPlanningTime", stats.QueryPlanningTimeInMillis, "Milliseconds")
	add("QueryQueueTime", stats.QueryQueueTimeInMillis, "Milliseconds")
	add("ServicePreProcessingTime", stats.ServicePreProcessingTimeInMillis, "Milliseconds")
	add("ServiceProcessingTime", stats.ServiceProcessingTimeInMillis, "Milliseconds")
	add("TotalExecutionTime", stats.TotalExecutionTimeInMillis, "Milliseconds")
	if len(samples) == 0 {
		return nil
	}
	return s.metrics.Publish(ctx, "AWS/Athena", samples)
}

// Cancellation owns the terminal state before native shutdown finishes. Preserve
// returned native measurements without publishing a second state-change event or
// overwriting cancellation with a stale successful engine callback.
func (s *Service) completeCancelled(query QueryRecord, result ExecutionResult) {
	err := s.repository.Update(s.lifetime, func(tx Transaction) error {
		current, err := tx.Query(query.Key)
		if err != nil {
			return err
		}
		return s.retainCancelled(tx, current, result)
	})
	if err != nil && s.lifetime.Err() == nil {
		slog.Error("retain cancelled Athena measurements", "query", query.Key.Name, "error", err)
	}
}

func (s *Service) retainCancelled(tx Transaction, current QueryRecord, result ExecutionResult) error {
	if queryState(current) != "CANCELLED" {
		return nil
	}
	if current.Data.Statistics == nil {
		current.Data.Statistics = &api.QueryExecutionStatistics{}
	}
	stats := current.Data.Statistics
	if stats.EngineExecutionTimeInMillis != nil {
		return nil
	}
	if result.StatementType != "" {
		current.Data.StatementType = new(api.StatementType(result.StatementType))
	}
	if result.SubstatementType != "" {
		current.Data.SubstatementType = new(api.String(result.SubstatementType))
	}
	stats.EngineExecutionTimeInMillis = new(api.Long(result.EngineMillis))
	stats.DataScannedInBytes = new(api.Long(result.DataScannedBytes))
	if current.Data.Status.SubmissionDateTime != nil && current.Data.Status.CompletionDateTime != nil {
		total := current.Data.Status.CompletionDateTime.Sub(*current.Data.Status.SubmissionDateTime).Milliseconds()
		stats.TotalExecutionTimeInMillis = new(api.Long(max(total, result.EngineMillis)))
	}
	if err := tx.PutQuery(current); err != nil {
		return err
	}
	caller := current.Caller
	caller.ParentEventID = current.ParentEventID
	ctx := awsctx.WithMetadata(tx.Context(), caller)
	return s.publishQueryMetrics(ctx, current)
}
