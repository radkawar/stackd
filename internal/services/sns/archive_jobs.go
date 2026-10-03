package sns

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

type archiveExpirationJobs struct{ s *Service }

func (j archiveExpirationJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	err = j.s.repository.View(ctx, func(r Reader) error {
		entry, exists, readErr := r.NextArchiveExpiration()
		job = scheduler.Job{Key: entry.Message.ID + "/" + entry.Message.Protocol, Due: entry.Expires, Version: entry.Sequence}
		found = exists
		return readErr
	})
	return
}

func (j archiveExpirationJobs) Run(ctx context.Context, job scheduler.Job) error {
	id, protocol, _ := strings.Cut(job.Key, "/")
	key := MessageKey{ID: id, Protocol: protocol}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		entry, err := tx.ArchiveEntry(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil || entry.Expires.After(j.s.clock.Now()) {
			return err
		}
		return tx.DeleteArchiveEntry(key)
	})
}

type archiveMetricJobs struct{ s *Service }

func (j archiveMetricJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	if j.s.metrics == nil {
		return
	}
	err = j.s.repository.View(ctx, func(r Reader) error {
		topic, exists, readErr := r.NextArchiveMetric()
		found = exists
		if exists {
			job = scheduler.Job{Key: topic.Key.ARN(), Due: topic.Archive.MetricDue}
		}
		return readErr
	})
	return
}

func (j archiveMetricJobs) Run(ctx context.Context, job scheduler.Job) error {
	parsed, err := arn.Parse(job.Key)
	if err != nil {
		return err
	}
	key := TopicKey{Scope: Scope{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}, Name: parsed.Resource}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region})
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		topic, err := tx.Topic(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil || topic.Archive == nil || !topic.Archive.MetricDue.Equal(job.Due) || job.Due.After(j.s.clock.Now()) {
			return err
		}
		messages, bytes, err := tx.ArchiveUsage(topic.ID)
		if err != nil {
			return err
		}
		now := j.s.clock.Now().UTC()
		dimensions := metricsapi.Dimensions{{Name: str[metricsapi.DimensionName]("TopicName"), Value: str[metricsapi.DimensionValue](key.Name)}}
		data := []metricsapi.MetricDatum{
			{MetricName: str[metricsapi.MetricName](metricArchivedMessages), Dimensions: dimensions, Timestamp: ptr(metricsapi.Timestamp(now)), Unit: str[metricsapi.StandardUnit]("None"), Value: ptr(metricsapi.DatapointValue(messages))},
			{MetricName: str[metricsapi.MetricName](metricArchivedBytes), Dimensions: dimensions, Timestamp: ptr(metricsapi.Timestamp(now)), Unit: str[metricsapi.StandardUnit]("None"), Value: ptr(metricsapi.DatapointValue(bytes))},
		}
		if err := j.s.metrics.Publish(tx.Context(), "AWS/SNS", data); err != nil {
			return err
		}
		// A service-time jump emits the current snapshot, not invented values
		// for historical hours whose archive contents are no longer retained.
		topic.Archive.MetricDue = now.Truncate(time.Hour).Add(time.Hour)
		return tx.PutTopic(topic)
	})
}
