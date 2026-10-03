package integrations

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/services/glue"
)

// PublishMetrics commits actual completed Spark task observations through the
// existing CloudWatch owner. Glue calls this in the transaction that acknowledges
// its retained observation, so reopening cannot duplicate the published delta.
// These final native counters are not synthetic Python-shell or DPU metrics.
func (a *GlueJobs) PublishMetrics(ctx context.Context, run glue.JobRunRecord) error {
	observed := run.SparkMetrics
	_, enabled := run.Arguments["--enable-metrics"]
	if !enabled || !observed.Observed {
		return nil
	}
	if a.Metrics == nil {
		return errors.New("glue CloudWatch metric publisher is not configured")
	}
	origin := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: run.Key.Partition, AccountID: run.Key.AccountID, Region: run.Key.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID, InvokedBy: "glue.amazonaws.com",
	})
	samples := [...]struct {
		name  string
		value int64
		unit  api.StandardUnit
	}{
		{"numCompletedTasks", observed.CompletedTasks, "Count"},
		{"numFailedTasks", observed.FailedTasks, "Count"},
		{"numKilledTasks", observed.KilledTasks, "Count"},
		{"numCompletedStages", observed.CompletedStages, "Count"},
		{"bytesRead", observed.BytesRead, "Bytes"},
		{"recordsRead", observed.RecordsRead, "Count"},
	}
	data := make([]api.MetricDatum, 0, 2*len(samples))
	for _, runID := range []string{run.ID, "ALL"} {
		dimensions := api.Dimensions{
			{Name: new(api.DimensionName("JobName")), Value: new(api.DimensionValue(run.Key.Name))},
			{Name: new(api.DimensionName("JobRunId")), Value: new(api.DimensionValue(runID))},
			{Name: new(api.DimensionName("Type")), Value: new(api.DimensionValue("count"))},
		}
		for _, sample := range samples {
			data = append(data, api.MetricDatum{
				MetricName: new(api.MetricName("glue.driver.aggregate." + sample.name)),
				Value:      new(api.DatapointValue(sample.value)), Unit: new(sample.unit),
				Timestamp: new(api.Timestamp(run.CompletedAt)), Dimensions: dimensions,
			})
		}
	}
	return a.Metrics.Publish(ctx, "Glue", data)
}
