package s3

import (
	"context"
	"errors"
	"strconv"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type replicationJobs struct{ service *Service }

func (source replicationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	found := false
	err := source.service.repository.View(ctx, func(reader Reader) error {
		pending, err := reader.NextReplicationJob()
		if err != nil || pending == nil {
			return err
		}
		job = scheduler.Job{Key: strconv.FormatInt(pending.Sequence, 10), Version: replicationJobVersion(*pending), Due: pending.Deadline()}
		found = true
		return nil
	})
	return job, found, err
}

func (source replicationJobs) Run(ctx context.Context, selected scheduler.Job) error {
	sequence, err := strconv.ParseInt(selected.Key, 10, 64)
	if err != nil {
		return err
	}
	s := source.service
	var job ReplicationJob
	var bucket BucketRecord
	err = s.repository.View(ctx, func(reader Reader) error {
		var err error
		job, err = reader.ReplicationJob(sequence)
		if err != nil {
			return err
		}
		bucket, err = reader.Bucket(job.Source.Bucket)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !job.Deadline().Equal(selected.Due) || replicationJobVersion(job) != selected.Version {
		return nil
	}
	ctx = replicationContext(ctx, job, bucket)
	if selected.Due.Before(job.Due) {
		return s.reportReplicationThreshold(ctx, selected, job, bucket)
	}
	var roleContext context.Context
	if s.replicationRoles == nil {
		err = denied()
	} else {
		roleContext, err = s.replicationRoles.Context(ctx, bucket, job.RoleARN)
	}
	if err != nil {
		var wire *awswire.Error
		if !errors.As(err, &wire) {
			return err
		}
		return s.repository.Update(ctx, func(tx Transaction) error {
			object, err := tx.ObjectVersion(job.Source)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			a := &replicationAttempt{job: job, sourceBucket: bucket, source: object,
				failure: &replicationFailure{operation: job.Operation, reason: "AssumeRoleNotPermitted"}}
			return s.commitReplication(tx, a, temporaryReplicationError(wire))
		})
	}
	var attempt *replicationAttempt
	err = s.repository.View(roleContext, func(reader Reader) error {
		var err error
		attempt, err = s.prepareReplication(reader, job)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	defer clear(attempt.source.EncryptionKey)
	wire := s.replicationEncryption(roleContext, attempt)
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.repository.Update(roleContext, func(tx Transaction) error {
		return s.commitReplication(tx, attempt, temporaryReplicationError(wire))
	})
}

func temporaryReplicationError(wire *awswire.Error) bool {
	if wire == nil {
		return false
	}
	switch wire.StatusCode {
	case 429, 500, 502, 503, 504:
		return true
	}
	switch wire.Code {
	case "ThrottlingException", "KMS.ThrottlingException", "DependencyTimeoutException", "KMS.DependencyTimeoutException":
		return true
	}
	return false
}

func (s *Service) commitReplication(tx Transaction, a *replicationAttempt, retry bool) error {
	current, err := tx.ReplicationJob(a.job.Sequence)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !current.Due.Equal(a.job.Due) || replicationJobVersion(current) != replicationJobVersion(a.job) {
		return nil
	}
	if !retry && (a.failure == nil || a.copiesObject()) {
		// KMS ran outside this transaction. A bucket recreated by another
		// account cannot inherit the authority checked for its previous owner.
		bucket, err := tx.Bucket(a.job.Destination.Bucket)
		if errors.Is(err, ErrNotFound) {
			a.rejectDestination(a.job.Operation, "DstBucketNotFound", failure("NoSuchBucket", "The specified bucket does not exist.", 404))
		} else if err != nil {
			return err
		} else if bucket.AccountID != a.destinationBucket.AccountID {
			a.rejectDestination(a.job.Operation, "DstPutObjectNotPermitted", denied())
		} else if bucket.Versioning != "Enabled" {
			a.rejectDestination(a.job.Operation, "DstBucketUnversioned", invalid("The destination bucket must have versioning enabled."))
		} else {
			a.destinationBucket = bucket
		}
		if a.failure == nil || a.copiesObject() {
			if err := s.applyReplica(tx, a); err != nil {
				return err
			}
		}
	}
	for _, result := range a.results {
		if err := s.record(tx.Context(), result.call, result.wire); err != nil {
			return err
		}
	}
	if retry {
		current.Attempts++
		current.Due = current.Due.Add(time.Minute)
		return tx.PutReplicationJob(&current)
	}
	status := "COMPLETED"
	if a.failure != nil {
		status = "FAILED"
	}
	if a.failure != nil && a.copiesObject() {
		if err := s.setReplicationState(tx, a.job, ReplicationObject, "COMPLETED"); err != nil {
			return err
		}
	}
	component := a.job.Operation
	if a.failure != nil {
		component = a.failure.operation
	}
	if err := s.setReplicationState(tx, a.job, component, status); err != nil {
		return err
	}
	if err := tx.DeleteReplicationJob(a.job.Sequence); err != nil {
		return err
	}
	return s.replicationOutcome(tx, a)
}

func (s *Service) setReplicationState(tx Transaction, job ReplicationJob, operation ReplicationOperation, status string) error {
	return tx.PutReplicationState(ReplicationState{Source: job.Source, Destination: job.Destination.Bucket,
		Operation: operation, Sequence: job.Sequence, Status: status})
}
