package s3

import (
	"context"
	"errors"
	"time"

	"stackd/internal/scheduler"
)

type replicationNotification struct {
	job           *ReplicationJob
	failureReason string
}

func (notification replicationNotification) fields() map[string]any {
	job := notification.job
	fields := map[string]any{
		"replicationRuleId": job.RuleID,
		"destinationBucket": job.Destination.Bucket.ARN(),
		"s3Operation":       string(job.Operation),
		"requestTime":       job.Created.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if notification.failureReason != "" {
		fields["failureReason"] = notification.failureReason
	}
	return fields
}

func (s *Service) replicationOutcome(tx Transaction, attempt *replicationAttempt) error {
	job := attempt.job
	if job.Destination.MetricsStatus == "Enabled" {
		// An initial partial tag failure leaves a successfully copied object.
		// Native metrics and notifications do not classify that object copy as failed.
		failed := attempt.failure != nil && !attempt.copiesObject()
		key := replicationMetricKey(attempt.sourceBucket, job.Destination, job.RuleID)
		at := job.Due.UTC().Truncate(time.Minute).Add(time.Minute)
		if err := tx.AddReplicationMetricOutcome(key, at, job.Destination.MetricsReadyAt, failed); err != nil {
			return err
		}
		if failed {
			c := &apiCall{eventID: job.ParentEventID}
			notification := &replicationNotification{job: &job, failureReason: attempt.failure.reason}
			return s.notifyObjectEvent(tx, c, attempt.sourceBucket, attempt.source, "Replication:OperationFailedReplication", nil, notification, job.Due)
		}
	}
	if job.ThresholdReported && attempt.failure == nil {
		c := &apiCall{eventID: job.ParentEventID}
		return s.notifyObjectEvent(tx, c, attempt.sourceBucket, attempt.source, "Replication:OperationReplicatedAfterThreshold", nil, &replicationNotification{job: &job}, job.Due)
	}
	return nil
}

func replicationJobVersion(job ReplicationJob) uint64 {
	version := uint64(job.Attempts)*2 + 1
	if job.ThresholdReported {
		version++
	}
	return version
}

func (s *Service) reportReplicationThreshold(ctx context.Context, selected scheduler.Job, job ReplicationJob, bucket BucketRecord) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.ReplicationJob(job.Sequence)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !current.Deadline().Equal(selected.Due) || replicationJobVersion(current) != selected.Version {
			return nil
		}
		object, err := tx.ObjectVersion(current.Source)
		if err != nil {
			return err
		}
		current.ThresholdReported = true
		if err := tx.PutReplicationJob(&current); err != nil {
			return err
		}
		c := &apiCall{eventID: current.ParentEventID}
		return s.notifyObjectEvent(tx, c, bucket, object, "Replication:OperationMissedThreshold", nil, &replicationNotification{job: &current}, selected.Due)
	})
}

func (s *Service) abandonObjectReplication(tx Transaction, c *apiCall, bucket BucketRecord, object ObjectRecord) error {
	jobs, err := tx.ReplicationJobs(object.VersionKey())
	if err != nil {
		return err
	}
	for i := range jobs {
		job := &jobs[i]
		if job.Destination.MetricsStatus == "Enabled" {
			if err := s.notifyObjectEvent(tx, c, bucket, object, "Replication:OperationNotTracked", nil, &replicationNotification{job: job}, s.clock.Now()); err != nil {
				return err
			}
		}
	}
	return nil
}
