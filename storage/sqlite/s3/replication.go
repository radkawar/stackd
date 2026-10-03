package s3

import (
	"database/sql"
	"errors"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) BucketReplication(key domain.BucketKey) (*domain.ReplicationConfiguration, error) {
	row, err := r.q.GetBucketReplication(r.ctx, sqlcgen.GetBucketReplicationParams{Partition: key.Partition, BucketName: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rules, err := r.q.GetBucketReplicationRules(r.ctx, sqlcgen.GetBucketReplicationRulesParams{Partition: key.Partition, BucketName: key.Name})
	if err != nil {
		return nil, err
	}
	out := &domain.ReplicationConfiguration{RoleARN: row.RoleArn, Rules: make([]domain.ReplicationRule, len(rules))}
	for i, rule := range rules {
		out.Rules[i] = domain.ReplicationRule{
			ID: rule.ID, Priority: rule.Priority, Enabled: rule.Enabled,
			Filter:                  domain.ReplicationFilter{Kind: rule.FilterKind, Prefix: rule.FilterPrefix},
			DeleteMarkerReplication: rule.DeleteMarkerReplication,
			SSEKMSObjects:           rule.SseKmsObjects, ReplicaModifications: rule.ReplicaModifications,
			Destination: domain.ReplicationDestination{
				Bucket: domain.BucketKey{Partition: rule.DestinationPartition, Name: rule.DestinationBucket},
				Region: rule.DestinationRegion, AccountID: rule.AccountID, OwnerOverride: rule.OwnerOverride,
				StorageClass: rule.StorageClass, KMSKeyID: rule.KmsKeyID,
				MetricsStatus: rule.MetricsStatus, MetricsMinutes: rule.MetricsMinutes,
				MetricsReadyAt: rule.MetricsReadyAt,
				TimeStatus:     rule.TimeStatus, TimeMinutes: rule.TimeMinutes,
			},
		}
	}
	tags, err := r.q.GetBucketReplicationFilterTags(r.ctx, sqlcgen.GetBucketReplicationFilterTagsParams{Partition: key.Partition, BucketName: key.Name})
	if err != nil {
		return nil, err
	}
	for _, tag := range tags {
		rule := &out.Rules[tag.RulePosition]
		rule.Filter.Tags = append(rule.Filter.Tags, domain.Tag{Key: tag.Key, Value: tag.Value})
	}
	return out, nil
}

func (w writer) ReplaceBucketReplication(key domain.BucketKey, config *domain.ReplicationConfiguration) error {
	if err := w.q.DeleteBucketReplication(w.ctx, sqlcgen.DeleteBucketReplicationParams{Partition: key.Partition, BucketName: key.Name}); err != nil {
		return err
	}
	if config == nil {
		return nil
	}
	if err := w.q.PutBucketReplication(w.ctx, sqlcgen.PutBucketReplicationParams{
		Partition: key.Partition, BucketName: key.Name, RoleArn: config.RoleARN,
	}); err != nil {
		return err
	}
	for position, rule := range config.Rules {
		if err := w.q.PutBucketReplicationRule(w.ctx, sqlcgen.PutBucketReplicationRuleParams{
			Partition: key.Partition, BucketName: key.Name, Position: int64(position),
			ID: rule.ID, Priority: rule.Priority, Enabled: rule.Enabled,
			FilterKind: rule.Filter.Kind, FilterPrefix: rule.Filter.Prefix,
			DeleteMarkerReplication: rule.DeleteMarkerReplication,
			SseKmsObjects:           rule.SSEKMSObjects, ReplicaModifications: rule.ReplicaModifications,
			DestinationPartition: rule.Destination.Bucket.Partition, DestinationBucket: rule.Destination.Bucket.Name,
			DestinationRegion: rule.Destination.Region,
			AccountID:         rule.Destination.AccountID, OwnerOverride: rule.Destination.OwnerOverride,
			StorageClass: rule.Destination.StorageClass, KmsKeyID: rule.Destination.KMSKeyID,
			MetricsStatus: rule.Destination.MetricsStatus, MetricsMinutes: rule.Destination.MetricsMinutes,
			MetricsReadyAt: rule.Destination.MetricsReadyAt.UTC(),
			TimeStatus:     rule.Destination.TimeStatus, TimeMinutes: rule.Destination.TimeMinutes,
		}); err != nil {
			return err
		}
		for tagPosition, tag := range rule.Filter.Tags {
			if err := w.q.PutBucketReplicationFilterTag(w.ctx, sqlcgen.PutBucketReplicationFilterTagParams{
				Partition: key.Partition, BucketName: key.Name, RulePosition: int64(position),
				Position: int64(tagPosition), Key: tag.Key, Value: tag.Value,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
