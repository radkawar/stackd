package s3

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) NextReplicationMetricPublication() (*domain.ReplicationMetricPublication, error) {
	row, err := r.q.NextReplicationMetricPublication(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := replicationMetricPublication(row)
	return &out, nil
}

func (r reader) ReplicationMetricPublication(key domain.ReplicationMetricKey, at time.Time) (*domain.ReplicationMetricPublication, error) {
	row, err := r.q.GetReplicationMetricPublication(r.ctx, sqlcgen.GetReplicationMetricPublicationParams{
		Partition: key.Source.Partition, BucketName: key.Source.Name,
		DestinationPartition: key.Destination.Partition, DestinationBucket: key.Destination.Name,
		AccountID: key.AccountID, SourceRegion: key.SourceRegion, DestinationRegion: key.DestinationRegion,
		RuleID: key.RuleID, At: at.UTC(),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := replicationMetricPublication(row)
	return &out, nil
}

func replicationMetricPublication(row sqlcgen.S3ReplicationMetricPublication) domain.ReplicationMetricPublication {
	return domain.ReplicationMetricPublication{
		Key: domain.ReplicationMetricKey{
			Source:      domain.BucketKey{Partition: row.Partition, Name: row.BucketName},
			Destination: domain.BucketKey{Partition: row.DestinationPartition, Name: row.DestinationBucket},
			AccountID:   row.AccountID, SourceRegion: row.SourceRegion, DestinationRegion: row.DestinationRegion,
			RuleID: row.RuleID,
		},
		At: row.At, ReadyAt: row.ReadyAt, Operations: row.Operations, Failed: row.Failed,
		Recurring: row.Recurring, Sampled: row.Sampled,
		Pending: domain.ReplicationPending{
			Operations: row.PendingOperations, Bytes: row.PendingBytes, Oldest: row.PendingOldest.Time,
		},
	}
}

func (r reader) ReplicationPending(key domain.ReplicationMetricKey, at time.Time) (domain.ReplicationPending, error) {
	counts, err := r.q.GetReplicationPendingCounts(r.ctx, sqlcgen.GetReplicationPendingCountsParams{
		Partition: key.Source.Partition, BucketName: key.Source.Name,
		DestinationPartition: key.Destination.Partition, DestinationBucket: key.Destination.Name,
		RuleID: key.RuleID, AccountID: key.AccountID, At: at.UTC(),
	})
	if err != nil {
		return domain.ReplicationPending{}, err
	}
	out := domain.ReplicationPending{Operations: counts.Operations, Bytes: counts.Bytes}
	if out.Operations == 0 {
		return out, nil
	}
	out.Oldest, err = r.q.GetOldestReplicationPending(r.ctx, sqlcgen.GetOldestReplicationPendingParams{
		Partition: key.Source.Partition, BucketName: key.Source.Name,
		DestinationPartition: key.Destination.Partition, DestinationBucket: key.Destination.Name,
		RuleID: key.RuleID, AccountID: key.AccountID, At: at.UTC(),
	})
	if err != nil {
		return domain.ReplicationPending{}, err
	}
	return out, nil
}

func (w writer) ReplaceReplicationMetricSchedules(source domain.BucketKey, rows []domain.ReplicationMetricPublication) error {
	if err := w.q.StopReplicationMetricSchedules(w.ctx, sqlcgen.StopReplicationMetricSchedulesParams{
		Partition: source.Partition, BucketName: source.Name,
	}); err != nil {
		return err
	}
	for _, row := range rows {
		if err := w.activateReplicationMetricSchedule(row.Key, row.At, row.ReadyAt); err != nil {
			return err
		}
	}
	if err := w.q.DeleteInactiveReplicationMetricSchedules(w.ctx, sqlcgen.DeleteInactiveReplicationMetricSchedulesParams{
		Partition: source.Partition, BucketName: source.Name,
	}); err != nil {
		return err
	}
	return nil
}

func (w writer) activateReplicationMetricSchedule(key domain.ReplicationMetricKey, at, readyAt time.Time) error {
	return w.q.ActivateReplicationMetricSchedule(w.ctx, sqlcgen.ActivateReplicationMetricScheduleParams{
		Partition: key.Source.Partition, BucketName: key.Source.Name,
		DestinationPartition: key.Destination.Partition, DestinationBucket: key.Destination.Name,
		AccountID: key.AccountID, SourceRegion: key.SourceRegion, DestinationRegion: key.DestinationRegion,
		RuleID: key.RuleID, At: at.UTC(), ReadyAt: readyAt.UTC(),
	})
}

func (w writer) AddReplicationMetricOutcome(key domain.ReplicationMetricKey, at, readyAt time.Time, failed bool) error {
	var failure int64
	if failed {
		failure = 1
	}
	return w.q.AddReplicationMetricOutcome(w.ctx, sqlcgen.AddReplicationMetricOutcomeParams{
		Partition: key.Source.Partition, BucketName: key.Source.Name,
		DestinationPartition: key.Destination.Partition, DestinationBucket: key.Destination.Name,
		AccountID: key.AccountID, SourceRegion: key.SourceRegion, DestinationRegion: key.DestinationRegion,
		RuleID: key.RuleID, At: at.UTC(), ReadyAt: readyAt.UTC(), Failed: failure,
	})
}

func (w writer) SampleReplicationMetricPublication(publication domain.ReplicationMetricPublication) error {
	key := publication.Key
	readyAt, err := w.q.SampleReplicationMetricPublication(w.ctx, sqlcgen.SampleReplicationMetricPublicationParams{
		PendingOperations: publication.Pending.Operations, PendingBytes: publication.Pending.Bytes,
		PendingOldest: sql.NullTime{Time: publication.Pending.Oldest.UTC(), Valid: !publication.Pending.Oldest.IsZero()},
		Partition:     key.Source.Partition, BucketName: key.Source.Name,
		DestinationPartition: key.Destination.Partition, DestinationBucket: key.Destination.Name,
		AccountID: key.AccountID, SourceRegion: key.SourceRegion, DestinationRegion: key.DestinationRegion,
		RuleID: key.RuleID, At: publication.At.UTC(),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return w.activateReplicationMetricSchedule(key, publication.At.Add(time.Minute), readyAt)
}

func (w writer) CompleteReplicationMetricPublication(publication domain.ReplicationMetricPublication) error {
	key := publication.Key
	return w.q.DeleteReplicationMetricPublication(w.ctx, sqlcgen.DeleteReplicationMetricPublicationParams{
		Partition: key.Source.Partition, BucketName: key.Source.Name,
		DestinationPartition: key.Destination.Partition, DestinationBucket: key.Destination.Name,
		AccountID: key.AccountID, SourceRegion: key.SourceRegion, DestinationRegion: key.DestinationRegion,
		RuleID: key.RuleID, At: publication.At.UTC(),
	})
}
