package s3

import (
	"database/sql"
	"errors"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) ReplicationStates(key domain.ObjectVersionKey) ([]domain.ReplicationState, error) {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	rows, err := r.q.GetReplicationStates(r.ctx, sqlcgen.GetReplicationStatesParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ReplicationState, len(rows))
	for i, row := range rows {
		out[i] = domain.ReplicationState{
			Source: key, Destination: domain.BucketKey{Partition: row.DestinationPartition, Name: row.DestinationBucket},
			Operation: domain.ReplicationOperation(row.Operation), Sequence: row.Sequence, Status: row.Status,
		}
	}
	return out, nil
}

func (w writer) PutReplicationState(state domain.ReplicationState) error {
	key := state.Source
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	return w.q.PutReplicationState(w.ctx, sqlcgen.PutReplicationStateParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
		DestinationPartition: state.Destination.Partition, DestinationBucket: state.Destination.Name,
		Operation: string(state.Operation), Sequence: state.Sequence, Status: state.Status,
	})
}

func (r reader) ReplicationJob(sequence int64) (domain.ReplicationJob, error) {
	row, err := r.q.GetReplicationJob(r.ctx, sequence)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ReplicationJob{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.ReplicationJob{}, err
	}
	return replicationJob(row), nil
}

func (r reader) ReplicationJobs(key domain.ObjectVersionKey) ([]domain.ReplicationJob, error) {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	rows, err := r.q.ReplicationJobsForVersion(r.ctx, sqlcgen.ReplicationJobsForVersionParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ReplicationJob, len(rows))
	for i, row := range rows {
		out[i] = replicationJob(row)
	}
	return out, nil
}

func (r reader) NextReplicationJob() (*domain.ReplicationJob, error) {
	row, err := r.q.NextReplicationAttempt(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := replicationJob(row)
	thresholdRow, err := r.q.NextReplicationThreshold(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return &out, nil
	}
	if err != nil {
		return nil, err
	}
	threshold := replicationJob(thresholdRow)
	deadline, thresholdDeadline := out.Deadline(), threshold.Deadline()
	if thresholdDeadline.Before(deadline) || thresholdDeadline.Equal(deadline) && threshold.Sequence < out.Sequence {
		out = threshold
	}
	return &out, nil
}

func replicationJob(row sqlcgen.S3ReplicationJob) domain.ReplicationJob {
	return domain.ReplicationJob{
		Sequence: row.Sequence,
		Source: domain.ObjectVersionKey{
			ObjectKey: domain.ObjectKey{Bucket: domain.BucketKey{Partition: row.Partition, Name: row.BucketName}, Name: row.ObjectName},
			VersionID: row.VersionID,
		},
		Destination: domain.ReplicationDestination{
			Bucket: domain.BucketKey{Partition: row.DestinationPartition, Name: row.DestinationBucket},
			Region: row.DestinationRegion, AccountID: row.AccountID, OwnerOverride: row.OwnerOverride,
			StorageClass: row.StorageClass, KMSKeyID: row.KmsKeyID,
			MetricsStatus: row.MetricsStatus, MetricsMinutes: row.MetricsMinutes,
			MetricsReadyAt: row.MetricsReadyAt,
			TimeStatus:     row.TimeStatus, TimeMinutes: row.TimeMinutes,
		},
		Operation: domain.ReplicationOperation(row.Operation), RoleARN: row.RoleArn, RuleID: row.RuleID,
		ParentEventID: row.ParentEventID, Created: row.Created, Due: row.Due, Attempts: int(row.Attempts),
		ThresholdReported: row.ThresholdReported,
	}
}

func (w writer) PutReplicationJob(job *domain.ReplicationJob) error {
	if job.Sequence == 0 {
		sequence, err := w.q.NextObjectSequence(w.ctx)
		if err != nil {
			return err
		}
		job.Sequence = sequence
	}
	key := job.Source
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	return w.q.PutReplicationJob(w.ctx, sqlcgen.PutReplicationJobParams{
		Sequence:  job.Sequence,
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
		DestinationPartition: job.Destination.Bucket.Partition, DestinationBucket: job.Destination.Bucket.Name,
		DestinationRegion: job.Destination.Region, AccountID: job.Destination.AccountID, OwnerOverride: job.Destination.OwnerOverride,
		StorageClass: job.Destination.StorageClass, KmsKeyID: job.Destination.KMSKeyID,
		MetricsStatus: job.Destination.MetricsStatus, MetricsMinutes: job.Destination.MetricsMinutes,
		MetricsReadyAt: job.Destination.MetricsReadyAt.UTC(),
		TimeStatus:     job.Destination.TimeStatus, TimeMinutes: job.Destination.TimeMinutes,
		Operation: string(job.Operation), RoleArn: job.RoleARN, RuleID: job.RuleID, ParentEventID: job.ParentEventID,
		Created: job.Created, Due: job.Due, Attempts: int64(job.Attempts),
		ThresholdReported: job.ThresholdReported,
	})
}

func (w writer) DeleteReplicationJob(sequence int64) error {
	return w.q.DeleteReplicationJob(w.ctx, sequence)
}

func (w writer) PutReplica(source domain.ObjectVersionKey, replica domain.ObjectRecord) error {
	if source.VersionID == "" {
		source.VersionID = "null"
	}
	if _, err := w.q.GetObjectVersion(w.ctx, sqlcgen.GetObjectVersionParams{
		Partition: source.Bucket.Partition, BucketName: source.Bucket.Name, Name: source.Name, VersionID: source.VersionID,
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ErrNotFound
		}
		return err
	}
	key := replica.Key
	bucket, err := w.q.GetBucket(w.ctx, sqlcgen.GetBucketParams{Partition: key.Bucket.Partition, Name: key.Bucket.Name})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ErrNotFound
		}
		return err
	}
	acl := replica.ACL
	if acl == nil {
		acl = domain.DefaultACL(key.Bucket.Partition, bucket.AccountID)
	}
	if replica.VersionID == "" {
		replica.VersionID = "null"
	}
	// Unlike a normal null-version PUT, replica insertion never replaces an
	// existing destination identity. The version insert enforces that conflict.
	if err := w.putObjectVersion(replica, *acl); err != nil {
		return err
	}
	encryptionKey, customerSalt, customerHash, customerMD5 := encryptionMetadata(replica)
	count, err := w.q.CopyReplicaData(w.ctx, sqlcgen.CopyReplicaDataParams{
		DestinationPartition: key.Bucket.Partition, DestinationBucket: key.Bucket.Name,
		DestinationName: key.Name, DestinationVersionID: replica.VersionID, EncryptionKey: encryptionKey,
		CustomerKeySalt: customerSalt, CustomerKeyHash: customerHash, CustomerKeyMd5: customerMD5,
		SourcePartition: source.Bucket.Partition, SourceBucket: source.Bucket.Name,
		SourceName: source.Name, SourceVersionID: source.VersionID,
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return domain.ErrNotFound
	}
	return w.q.CopyReplicaParts(w.ctx, sqlcgen.CopyReplicaPartsParams{
		DestinationPartition: key.Bucket.Partition, DestinationBucket: key.Bucket.Name,
		DestinationName: key.Name, DestinationVersionID: replica.VersionID,
		SourcePartition: source.Bucket.Partition, SourceBucket: source.Bucket.Name,
		SourceName: source.Name, SourceVersionID: source.VersionID,
	})
}
