package sqs

import (
	"database/sql"
	"errors"
	"time"

	"stackd/storage/sqlite"
	"stackd/storage/sqlite/sqs/internal/sqlcgen"
	domain "stackd/storage/sqs"
)

func (r reader) Queue(key domain.QueueKey) (domain.QueueRecord, error) {
	row, err := r.q.GetQueue(r.ctx, sqlcgen.GetQueueParams{Partition: key.Partition, Account: key.Account, Region: key.Region, Name: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.QueueRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.QueueRecord{}, err
	}
	return r.queue(row)
}

func (r reader) Queues() ([]domain.QueueRecord, error) {
	rows, err := r.q.ListQueues(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.QueueRecord, 0, len(rows))
	for _, row := range rows {
		queue, err := r.queue(row)
		if err != nil {
			return nil, err
		}
		out = append(out, queue)
	}
	return out, nil
}

func (r reader) NextMetricQueue() (domain.QueueRecord, error) {
	row, err := r.q.NextMetricQueue(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.QueueRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.QueueRecord{}, err
	}
	return r.queue(row)
}

func (r reader) queue(row sqlcgen.SqsQueue) (domain.QueueRecord, error) {
	result := domain.QueueRecord{
		Key: domain.QueueKey{Partition: row.Partition, Account: row.Account, Region: row.Region, Name: row.Name},
		ID:  row.ID, Created: row.Created, Modified: row.Modified, Purged: row.Purged, Sequence: uint64(row.Sequence), ManagedEncryptionKey: row.EncryptionKey,
		MetricActiveUntil: row.MetricActiveUntil.Time, NextMetricSample: row.NextMetricSample.Time,
		Configuration: domain.QueueConfiguration{
			DelaySeconds: int(row.DelaySeconds), MaximumMessageSize: int(row.MaximumMessageSize), RetentionSeconds: int(row.RetentionSeconds), VisibilitySeconds: int(row.VisibilitySeconds), WaitSeconds: int(row.WaitSeconds),
			FIFO: row.Fifo, ContentDeduplication: row.ContentDeduplication, ManagedSSE: row.ManagedSse, DeduplicationScope: row.DeduplicationScope, Throughput: row.Throughput, Policy: row.Policy,
			KMSKey: row.KmsKey, KMSReuseSeconds: int(row.KmsReuseSeconds), DeadLetterTargetARN: row.DeadLetterTargetArn, MaxReceiveCount: int(row.MaxReceiveCount), RedrivePermission: row.RedrivePermission,
		},
	}
	tags, err := r.q.ListQueueTags(r.ctx, row.ID)
	if err != nil {
		return domain.QueueRecord{}, err
	}
	for _, tag := range tags {
		result.Tags = append(result.Tags, domain.QueueTag{Key: tag.TagKey, Value: tag.TagValue})
	}
	principals, err := r.q.ListPolicyPrincipals(r.ctx, row.ID)
	if err != nil {
		return domain.QueueRecord{}, err
	}
	if len(principals) > 0 {
		result.Configuration.PolicyPrincipals = make(map[string]string, len(principals))
		for _, principal := range principals {
			result.Configuration.PolicyPrincipals[principal.Arn] = principal.PrincipalID
		}
	}
	sources, err := r.q.ListRedriveSources(r.ctx, row.ID)
	if err != nil {
		return domain.QueueRecord{}, err
	}
	for _, source := range sources {
		result.Configuration.RedriveSources = append(result.Configuration.RedriveSources, source.Arn)
	}
	return result, nil
}

func (w writer) PutQueue(record domain.QueueRecord) error {
	c := record.Configuration
	if err := w.q.PutQueue(w.ctx, sqlcgen.PutQueueParams{
		Partition: record.Key.Partition, Account: record.Key.Account, Region: record.Key.Region, Name: record.Key.Name, ID: record.ID,
		Created: record.Created, Modified: record.Modified, Purged: record.Purged, Sequence: sqlite.Uint64(record.Sequence), EncryptionKey: record.ManagedEncryptionKey,
		MetricActiveUntil: sql.NullTime{Time: record.MetricActiveUntil, Valid: !record.MetricActiveUntil.IsZero()},
		NextMetricSample:  sql.NullTime{Time: record.NextMetricSample, Valid: !record.NextMetricSample.IsZero()},
		DelaySeconds:      int64(c.DelaySeconds), MaximumMessageSize: int64(c.MaximumMessageSize), RetentionSeconds: int64(c.RetentionSeconds), VisibilitySeconds: int64(c.VisibilitySeconds), WaitSeconds: int64(c.WaitSeconds),
		Fifo: c.FIFO, ContentDeduplication: c.ContentDeduplication, ManagedSse: c.ManagedSSE, DeduplicationScope: c.DeduplicationScope, Throughput: c.Throughput, Policy: c.Policy,
		KmsKey: c.KMSKey, KmsReuseSeconds: int64(c.KMSReuseSeconds), DeadLetterTargetArn: c.DeadLetterTargetARN, MaxReceiveCount: int64(c.MaxReceiveCount), RedrivePermission: c.RedrivePermission,
	}); err != nil {
		return err
	}
	if err := w.q.ClearQueueTags(w.ctx, record.ID); err != nil {
		return err
	}
	for _, tag := range record.Tags {
		if err := w.q.InsertQueueTag(w.ctx, sqlcgen.InsertQueueTagParams{QueueID: record.ID, TagKey: tag.Key, TagValue: tag.Value}); err != nil {
			return err
		}
	}
	if err := w.q.ClearPolicyPrincipals(w.ctx, record.ID); err != nil {
		return err
	}
	for arn, id := range c.PolicyPrincipals {
		if err := w.q.InsertPolicyPrincipal(w.ctx, sqlcgen.InsertPolicyPrincipalParams{QueueID: record.ID, Arn: arn, PrincipalID: id}); err != nil {
			return err
		}
	}
	if err := w.q.ClearRedriveSources(w.ctx, record.ID); err != nil {
		return err
	}
	for i, source := range c.RedriveSources {
		if err := w.q.InsertRedriveSource(w.ctx, sqlcgen.InsertRedriveSourceParams{QueueID: record.ID, Position: int64(i), Arn: source}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteQueue(key domain.QueueKey) error {
	count, err := w.q.DeleteQueue(w.ctx, sqlcgen.DeleteQueueParams{Partition: key.Partition, Account: key.Account, Region: key.Region, Name: key.Name})
	if err == nil && count == 0 {
		return domain.ErrNotFound
	}
	return err
}

func (r reader) DeletedAt(key domain.QueueKey) (time.Time, error) {
	at, err := r.q.GetDeletedQueue(r.ctx, sqlcgen.GetDeletedQueueParams{Partition: key.Partition, Account: key.Account, Region: key.Region, Name: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	return at, err
}

func (w writer) SetDeletedAt(key domain.QueueKey, at time.Time) error {
	return w.q.PutDeletedQueue(w.ctx, sqlcgen.PutDeletedQueueParams{Partition: key.Partition, Account: key.Account, Region: key.Region, Name: key.Name, DeletedAt: at})
}
