package eventbridge

import (
	"context"
	"strings"
	"time"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// MetricPublisher commits service-owned samples in the source transaction,
// independently of customer PutMetricData permissions.
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}

type metricJobs struct{ s *Service }

func (j metricJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	if j.s.metrics == nil {
		return
	}
	err = j.s.repository.View(ctx, func(r Reader) error {
		key, exists, err := r.NextMetricPublication()
		if err != nil || !exists {
			return err
		}
		job = scheduler.Job{Key: key.Partition + ":" + key.Account + ":" + key.Region, Due: key.Minute.Add(time.Minute)}
		found = true
		return nil
	})
	return
}

func (j metricJobs) Run(ctx context.Context, job scheduler.Job) error {
	partition, rest, _ := strings.Cut(job.Key, ":")
	account, region, _ := strings.Cut(rest, ":")
	key := MetricPublicationKey{Scope: Scope{Partition: partition, Account: account, Region: region}, Minute: job.Due.Add(-time.Minute)}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: partition, AccountID: account, Region: region})
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		samples, err := tx.MetricSamples(key)
		if err != nil || len(samples) == 0 {
			return err
		}
		data := make([]metricsapi.MetricDatum, 0, len(samples))
		for _, sample := range samples {
			var dimensions metricsapi.Dimensions
			if sample.EventBusName != "" {
				dimensions = append(dimensions, metricsapi.Dimension{Name: ptr(metricsapi.DimensionName("EventBusName")), Value: ptr(metricsapi.DimensionValue(sample.EventBusName))})
			}
			if sample.RuleName != "" {
				dimensions = append(dimensions, metricsapi.Dimension{Name: ptr(metricsapi.DimensionName("RuleName")), Value: ptr(metricsapi.DimensionValue(sample.RuleName))})
			}
			if sample.Source != "" {
				dimensions = append(dimensions, metricsapi.Dimension{Name: ptr(metricsapi.DimensionName("Source")), Value: ptr(metricsapi.DimensionValue(sample.Source))})
			}
			unit := metricsapi.StandardUnit("Count")
			if strings.HasSuffix(sample.Name, "Latency") {
				unit = "Milliseconds"
			} else if sample.Name == "PutEventsRequestSize" {
				unit = "Bytes"
			}
			datum := metricsapi.MetricDatum{MetricName: ptr(metricsapi.MetricName(sample.Name)),
				Dimensions: dimensions, Timestamp: ptr(metricsapi.Timestamp(key.Minute)), Unit: &unit}
			switch sample.Name {
			case "TriggeredRules", "Invocations", "FailedInvocations", "InvocationsSentToDlq", "InvocationsFailedToBeSentToDlq":
				// Native legacy counters have a zero minimum and no percentile
				// samples, even when every counted observation is positive.
				datum.StatisticValues = &metricsapi.StatisticSet{
					SampleCount: ptr(metricsapi.DatapointValue(sample.SampleCount)),
					Sum:         ptr(metricsapi.DatapointValue(sample.Value * float64(sample.SampleCount))),
					Minimum:     ptr(metricsapi.DatapointValue(0)), Maximum: ptr(metricsapi.DatapointValue(sample.Value)),
				}
			default:
				datum.Values = metricsapi.Values{metricsapi.DatapointValue(sample.Value)}
				datum.Counts = metricsapi.Counts{metricsapi.DatapointValue(sample.SampleCount)}
			}
			data = append(data, datum)
		}
		if err := j.s.metrics.Publish(tx.Context(), "AWS/Events", data); err != nil {
			return err
		}
		return tx.DeleteMetricPublication(key)
	})
}
