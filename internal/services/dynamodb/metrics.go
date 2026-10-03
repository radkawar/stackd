package dynamodb

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// MetricPublisher joins service-owned observations to the source transaction.
// Publication does not borrow the customer's cloudwatch:PutMetricData permission.
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}

const (
	metricConsumedRead        = "ConsumedReadCapacityUnits"
	metricConsumedWrite       = "ConsumedWriteCapacityUnits"
	metricConditionalFailures = "ConditionalCheckFailedRequests"
	metricReadThrottle        = "ReadThrottleEvents"
	metricWriteThrottle       = "WriteThrottleEvents"
	metricThrottledRequests   = "ThrottledRequests"
)

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

type metricJobs struct{ s *Service }

func (j metricJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	if j.s.metrics == nil {
		return
	}
	err = j.s.repository.View(ctx, func(r Reader) error {
		key, err := r.NextMetricPublication()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		job, found = scheduler.Job{Key: key.Table.ARN(), Due: key.Minute.Add(time.Minute)}, true
		return nil
	})
	return
}

func (j metricJobs) Run(ctx context.Context, job scheduler.Job) error {
	ctx, table, err := metricContext(ctx, job.Key)
	if err != nil {
		return err
	}
	key := MetricPublicationKey{Table: table, Minute: job.Due.Add(-time.Minute)}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		samples, err := tx.MetricSamples(key)
		if err != nil || len(samples) == 0 {
			return err
		}
		if err := j.s.publishMetrics(tx.Context(), key, samples); err != nil {
			return err
		}
		return tx.DeleteMetricPublication(key)
	})
}

func metricContext(ctx context.Context, resource string) (context.Context, TableKey, error) {
	parsed, err := arn.Parse(resource)
	if err != nil {
		return ctx, TableKey{}, err
	}
	key := TableKey{Scope: Scope{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}, Name: strings.TrimPrefix(parsed.Resource, "table/")}
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region}), key, nil
}

func (s *Service) publishMetrics(ctx context.Context, key MetricPublicationKey, samples []MetricSample) error {
	at, unit := metricsapi.Timestamp(key.Minute), metricsapi.StandardUnitCount
	data := make([]metricsapi.MetricDatum, 0, len(samples))
	for _, sample := range samples {
		dimensions := metricsapi.Dimensions{{Name: new(metricsapi.DimensionName("TableName")), Value: new(metricsapi.DimensionValue(key.Table.Name))}}
		if sample.IndexName != "" {
			dimensions = append(dimensions, metricsapi.Dimension{Name: new(metricsapi.DimensionName("GlobalSecondaryIndexName")), Value: new(metricsapi.DimensionValue(sample.IndexName))})
		}
		if sample.Operation != "" {
			dimensions = append(dimensions, metricsapi.Dimension{Name: new(metricsapi.DimensionName("Operation")), Value: new(metricsapi.DimensionValue(sample.Operation))})
		}
		if sample.OperationType != "" {
			dimensions = append(dimensions, metricsapi.Dimension{Name: new(metricsapi.DimensionName("OperationType")), Value: new(metricsapi.DimensionValue(sample.OperationType))})
		}
		if sample.Verb != "" {
			dimensions = append(dimensions, metricsapi.Dimension{Name: new(metricsapi.DimensionName("Verb")), Value: new(metricsapi.DimensionValue(sample.Verb))})
		}
		datum := metricsapi.MetricDatum{
			MetricName: new(metricsapi.MetricName(sample.Name)), Dimensions: dimensions,
			Timestamp: &at, Unit: &unit,
			Values: metricsapi.Values{metricsapi.DatapointValue(sample.Value)},
			Counts: metricsapi.Counts{metricsapi.DatapointValue(sample.SampleCount)},
		}
		data = append(data, datum)
		if sample.Name == metricConsumedWrite {
			// Native regional writes publish both the ordinary series and the
			// Source=Customer series; they are separate CloudWatch identities.
			datum.Dimensions = make(metricsapi.Dimensions, len(dimensions)+1)
			copy(datum.Dimensions, dimensions)
			datum.Dimensions[len(dimensions)] = metricsapi.Dimension{Name: new(metricsapi.DimensionName("Source")), Value: new(metricsapi.DimensionValue("Customer"))}
			data = append(data, datum)
		}
	}
	return s.metrics.Publish(ctx, "AWS/DynamoDB", data)
}

type tableMetricJobs struct{ s *Service }

func (j tableMetricJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	if j.s.metrics == nil {
		return
	}
	err = j.s.repository.View(ctx, func(r Reader) error {
		table, err := r.NextMetricTable()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		job, found = scheduler.Job{Key: table.Key.ARN(), Due: table.MetricsNextAt}, true
		return nil
	})
	return
}

func (j tableMetricJobs) Run(ctx context.Context, job scheduler.Job) error {
	ctx, key, err := metricContext(ctx, job.Key)
	if err != nil {
		return err
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		table, err := tx.Table(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !table.MetricsNextAt.Equal(job.Due) || value(table.Data.TableStatus) != "ACTIVE" && value(table.Data.TableStatus) != "UPDATING" {
			return nil
		}
		// Like other source gauges, sample current state once after a clock
		// jump. The repository has no historical capacity snapshots to backdate.
		minute := j.s.clock.Now().UTC().Truncate(time.Minute)
		gauges := table.MetricsNextAt.IsZero() || minute.Minute()%5 == 0
		consumed, throughput := tableMetricSamples(&table, gauges)
		if !table.MetricsNextAt.IsZero() {
			// Zero is an observation about a completed minute, not a partial
			// current bucket. Publish it atomically with that minute's writes
			// and reads so an alarm never sees a premature idle value.
			publication := MetricPublicationKey{Table: key, Minute: minute.Add(-time.Minute)}
			if err := tx.AddMetricSamples(publication, consumed); err != nil {
				return err
			}
		}
		if len(throughput) != 0 {
			if err := j.s.publishMetrics(tx.Context(), MetricPublicationKey{Table: key, Minute: minute}, throughput); err != nil {
				return err
			}
		}
		table.MetricsNextAt = minute.Add(time.Minute)
		return tx.PutTable(table)
	})
}
