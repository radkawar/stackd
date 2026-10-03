package ecs

import (
	"context"
	"strings"
	"time"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// MetricPublisher commits service-owned observations in the source transaction,
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
		job = scheduler.Job{Key: key.Partition + ":" + key.AccountID + ":" + key.Region + ":" + key.Name + ":" + key.ServiceName, Due: key.Due}
		found = true
		return nil
	})
	return
}

func (j metricJobs) Run(ctx context.Context, job scheduler.Job) error {
	partition, rest, _ := strings.Cut(job.Key, ":")
	account, rest, _ := strings.Cut(rest, ":")
	region, rest, _ := strings.Cut(rest, ":")
	cluster, service, _ := strings.Cut(rest, ":")
	key := MetricPublicationKey{ServiceKey: ServiceKey{ClusterKey: ClusterKey{Scope: Scope{Partition: partition, AccountID: account, Region: region}, Name: cluster}, ServiceName: service}, Due: job.Due}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: partition, AccountID: account, Region: region, InvokedBy: ServicePrincipal})
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		samples, err := tx.MetricSamples(key)
		if err != nil || len(samples) == 0 {
			return err
		}
		dimensions := metricsapi.Dimensions{
			{Name: new(metricsapi.DimensionName("ClusterName")), Value: new(metricsapi.DimensionValue(cluster))},
			{Name: new(metricsapi.DimensionName("ServiceName")), Value: new(metricsapi.DimensionValue(service))},
		}
		data := make([]metricsapi.MetricDatum, 0, len(samples))
		for _, sample := range samples {
			unit := metricsapi.StandardUnit("Percent")
			if sample.Name == metricLiveTaskCount {
				unit = "Count"
			}
			resolution := metricsapi.StorageResolution(60)
			if sample.Resolution == 20 {
				resolution = 1
			}
			data = append(data, metricsapi.MetricDatum{
				MetricName: new(metricsapi.MetricName(sample.Name)), Dimensions: dimensions,
				Timestamp: new(metricsapi.Timestamp(key.Due.Add(-time.Duration(sample.Resolution) * time.Second))),
				Unit:      &unit, StorageResolution: &resolution,
				StatisticValues: &metricsapi.StatisticSet{
					Minimum: new(metricsapi.DatapointValue(sample.Minimum)), Maximum: new(metricsapi.DatapointValue(sample.Maximum)),
					Sum: new(metricsapi.DatapointValue(sample.Sum / float64(sample.Count))), SampleCount: new(metricsapi.DatapointValue(1)),
				},
			})
		}
		if err := j.s.metrics.Publish(tx.Context(), "AWS/ECS", data); err != nil {
			return err
		}
		return tx.DeleteMetricPublication(key)
	})
}
