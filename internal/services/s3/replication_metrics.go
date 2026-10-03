package s3

import (
	"context"
	"encoding/json"
	"time"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// MetricPublisher records source-owned S3 samples in CloudWatch, optionally
// joining a source transaction. Calls borrow no customer PutMetricData permission.
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}

func replicationMetricKey(bucket BucketRecord, destination ReplicationDestination, ruleID string) ReplicationMetricKey {
	return ReplicationMetricKey{Source: bucket.Key, Destination: destination.Bucket, AccountID: bucket.AccountID,
		SourceRegion: bucket.Region, DestinationRegion: destination.Region, RuleID: ruleID}
}

func (s *Service) configureReplicationMetrics(tx Transaction, bucket BucketRecord, configuration *ReplicationConfiguration) error {
	var schedules []ReplicationMetricPublication
	if configuration != nil {
		previous, err := tx.BucketReplication(bucket.Key)
		if err != nil {
			return err
		}
		ready := map[ReplicationMetricKey]time.Time{}
		if previous != nil {
			for _, rule := range previous.Rules {
				if rule.Enabled && rule.Destination.TimeStatus == "Enabled" {
					ready[replicationMetricKey(bucket, rule.Destination, rule.ID)] = rule.Destination.MetricsReadyAt
				}
			}
		}
		now := s.clock.Now().UTC()
		at := now.Truncate(time.Minute).Add(time.Minute)
		for i := range configuration.Rules {
			rule := &configuration.Rules[i]
			if !rule.Enabled || rule.Destination.MetricsStatus != "Enabled" {
				continue
			}
			if s.metrics == nil {
				return unsupported("Native replication metrics are not configured.")
			}
			key := replicationMetricKey(bucket, rule.Destination, rule.ID)
			if rule.Destination.TimeStatus == "Enabled" {
				if retained, exists := ready[key]; exists {
					rule.Destination.MetricsReadyAt = retained
				} else {
					rule.Destination.MetricsReadyAt = now.Add(15 * time.Minute)
				}
			}
			schedules = append(schedules, ReplicationMetricPublication{
				Key: key, At: at, ReadyAt: rule.Destination.MetricsReadyAt, Recurring: true,
			})
		}
	}
	return tx.ReplaceReplicationMetricSchedules(bucket.Key, schedules)
}

type replicationMetricJobs struct{ service *Service }

type replicationMetricJobKey struct {
	Key ReplicationMetricKey
	At  time.Time
}

func (source replicationMetricJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	found := false
	err := source.service.repository.View(ctx, func(reader Reader) error {
		publication, err := reader.NextReplicationMetricPublication()
		if err != nil || publication == nil {
			return err
		}
		key, err := json.Marshal(replicationMetricJobKey{Key: publication.Key, At: publication.At})
		if err != nil {
			return err
		}
		job, found = scheduler.Job{Key: string(key), Due: publication.Deadline()}, true
		return nil
	})
	return job, found, err
}

func (source replicationMetricJobs) Run(ctx context.Context, job scheduler.Job) error {
	var selected replicationMetricJobKey
	if err := json.Unmarshal([]byte(job.Key), &selected); err != nil {
		return err
	}
	key := selected.Key
	s := source.service
	if s.metrics == nil {
		return unsupported("Native replication metrics are not configured.")
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		publication, err := tx.ReplicationMetricPublication(key, selected.At)
		if err != nil || publication == nil {
			return err
		}
		if !publication.Deadline().Equal(job.Due) {
			return nil
		}
		if publication.Recurring {
			pending, err := tx.ReplicationPending(key, publication.At)
			if err != nil {
				return err
			}
			publication.Pending = pending
			if err := tx.SampleReplicationMetricPublication(*publication); err != nil {
				return err
			}
		}
		if publication.ReadyAt.After(job.Due) {
			return nil
		}
		dimensions := metricsapi.Dimensions{
			{Name: new(metricsapi.DimensionName("SourceBucket")), Value: new(metricsapi.DimensionValue(key.Source.Name))},
			{Name: new(metricsapi.DimensionName("DestinationBucket")), Value: new(metricsapi.DimensionValue(key.Destination.Name))},
			{Name: new(metricsapi.DimensionName("RuleId")), Value: new(metricsapi.DimensionValue(key.RuleID))},
		}
		at := metricsapi.Timestamp(publication.At.Add(-time.Minute))
		if publication.Recurring || publication.Sampled {
			pending := publication.Pending
			latency := float64(0)
			if pending.Operations != 0 {
				latency = publication.At.Sub(pending.Oldest).Seconds()
			}
			data := []metricsapi.MetricDatum{
				{MetricName: new(metricsapi.MetricName("BytesPendingReplication")), Dimensions: dimensions, Timestamp: &at, Unit: new(metricsapi.StandardUnit("Bytes")), Value: new(metricsapi.DatapointValue(pending.Bytes))},
				{MetricName: new(metricsapi.MetricName("OperationsPendingReplication")), Dimensions: dimensions, Timestamp: &at, Unit: new(metricsapi.StandardUnit("Count")), Value: new(metricsapi.DatapointValue(pending.Operations))},
				{MetricName: new(metricsapi.MetricName("ReplicationLatency")), Dimensions: dimensions, Timestamp: &at, Unit: new(metricsapi.StandardUnit("Seconds")), Value: new(metricsapi.DatapointValue(latency))},
			}
			if err := s.metrics.Publish(replicationMetricContext(tx.Context(), key, key.DestinationRegion), "AWS/S3", data); err != nil {
				return err
			}
		}
		if publication.Operations != 0 {
			// AWS reports the failure total as both extrema while SampleCount
			// counts all processed operations. Do not clamp it around Average.
			failed := metricsapi.DatapointValue(publication.Failed)
			data := []metricsapi.MetricDatum{{MetricName: new(metricsapi.MetricName("OperationsFailedReplication")),
				Dimensions: dimensions, Timestamp: &at, Unit: new(metricsapi.StandardUnit("Count")),
				StatisticValues: &metricsapi.StatisticSet{SampleCount: new(metricsapi.DatapointValue(publication.Operations)), Sum: &failed, Minimum: &failed, Maximum: &failed},
			}}
			if err := s.metrics.Publish(replicationMetricContext(tx.Context(), key, key.SourceRegion), "AWS/S3", data); err != nil {
				return err
			}
		}
		return tx.CompleteReplicationMetricPublication(*publication)
	})
}

func replicationMetricContext(ctx context.Context, key ReplicationMetricKey, region string) context.Context {
	m := awsctx.Metadata{Partition: key.Source.Partition, AccountID: key.AccountID, Region: region, InvokedBy: "s3.amazonaws.com"}
	return awsctx.WithMetadata(ctx, m)
}
