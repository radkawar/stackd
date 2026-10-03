package s3

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) BucketLifecycle(key domain.BucketKey) (*domain.LifecycleConfiguration, error) {
	row, err := r.q.GetBucketLifecycle(r.ctx, sqlcgen.GetBucketLifecycleParams{Partition: key.Partition, BucketName: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rules, err := r.q.GetBucketLifecycleRules(r.ctx, sqlcgen.GetBucketLifecycleRulesParams{Partition: key.Partition, BucketName: key.Name})
	if err != nil {
		return nil, err
	}
	out := &domain.LifecycleConfiguration{
		MinimumObjectSize: row.MinimumObjectSize, NextScan: row.NextScan, ParentEventID: row.ParentEventID,
		Rules: make([]domain.LifecycleRule, len(rules)),
	}
	for i, row := range rules {
		rule := &out.Rules[i]
		rule.ID, rule.Enabled, rule.AbortIncompleteDays = row.ID, row.Enabled, row.AbortIncompleteDays
		rule.Filter = domain.ObjectFilter{
			Kind: row.FilterKind, Prefix: row.FilterPrefix,
			ObjectSizeGreaterThan: row.ObjectSizeGreaterThan, ObjectSizeLessThan: row.ObjectSizeLessThan,
		}
		if row.ExpirationDate != nil || row.ExpirationDays != nil || row.ExpiredObjectDeleteMarker != nil {
			rule.Expiration = &domain.LifecycleExpiration{
				LifecycleWhen:             domain.LifecycleWhen{Date: row.ExpirationDate, Days: row.ExpirationDays},
				ExpiredObjectDeleteMarker: row.ExpiredObjectDeleteMarker,
			}
		}
		if row.NoncurrentExpirationDays != nil {
			rule.NoncurrentExpiration = &domain.LifecycleNoncurrentExpiration{
				Days: *row.NoncurrentExpirationDays, NewerNoncurrentVersions: row.NoncurrentExpirationNewerVersions,
			}
		}
	}
	tags, err := r.q.GetBucketLifecycleTags(r.ctx, sqlcgen.GetBucketLifecycleTagsParams{Partition: key.Partition, BucketName: key.Name})
	if err != nil {
		return nil, err
	}
	for _, tag := range tags {
		rule := &out.Rules[tag.RulePosition]
		rule.Filter.Tags = append(rule.Filter.Tags, domain.Tag{Key: tag.Key, Value: tag.Value})
	}
	transitions, err := r.q.GetBucketLifecycleTransitions(r.ctx, sqlcgen.GetBucketLifecycleTransitionsParams{Partition: key.Partition, BucketName: key.Name})
	if err != nil {
		return nil, err
	}
	for _, transition := range transitions {
		rule := &out.Rules[transition.RulePosition]
		if transition.Noncurrent {
			rule.NoncurrentTransitions = append(rule.NoncurrentTransitions, domain.LifecycleNoncurrentTransition{
				LifecycleNoncurrentExpiration: domain.LifecycleNoncurrentExpiration{Days: *transition.Days, NewerNoncurrentVersions: transition.NewerNoncurrentVersions},
				StorageClass:                  transition.StorageClass,
			})
		} else {
			rule.Transitions = append(rule.Transitions, domain.LifecycleTransition{
				LifecycleWhen: domain.LifecycleWhen{Date: transition.Date, Days: transition.Days}, StorageClass: transition.StorageClass,
			})
		}
	}
	return out, nil
}

func (r reader) NextLifecycleScan() (*domain.BucketScan, error) {
	row, err := r.q.NextLifecycleScan(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &domain.BucketScan{Bucket: domain.BucketKey{Partition: row.Partition, Name: row.BucketName}, Due: *row.NextScan}, nil
}

func (w writer) AdvanceLifecycleScan(key domain.BucketKey, due time.Time) error {
	return w.q.AdvanceLifecycleScan(w.ctx, sqlcgen.AdvanceLifecycleScanParams{Partition: key.Partition, BucketName: key.Name, NextScan: new(due.UTC())})
}

func (w writer) ReplaceBucketLifecycle(key domain.BucketKey, config *domain.LifecycleConfiguration) error {
	if err := w.q.DeleteBucketLifecycle(w.ctx, sqlcgen.DeleteBucketLifecycleParams{Partition: key.Partition, BucketName: key.Name}); err != nil {
		return err
	}
	if config == nil {
		return nil
	}
	if err := w.q.PutBucketLifecycle(w.ctx, sqlcgen.PutBucketLifecycleParams{
		Partition: key.Partition, BucketName: key.Name, MinimumObjectSize: config.MinimumObjectSize, NextScan: config.NextScan, ParentEventID: config.ParentEventID,
	}); err != nil {
		return err
	}
	for position, rule := range config.Rules {
		row := sqlcgen.PutBucketLifecycleRuleParams{
			Partition: key.Partition, BucketName: key.Name, Position: int64(position), ID: rule.ID, Enabled: rule.Enabled,
			FilterKind: rule.Filter.Kind, FilterPrefix: rule.Filter.Prefix,
			ObjectSizeGreaterThan: rule.Filter.ObjectSizeGreaterThan, ObjectSizeLessThan: rule.Filter.ObjectSizeLessThan,
			AbortIncompleteDays: rule.AbortIncompleteDays,
		}
		if rule.Expiration != nil {
			row.ExpirationDate, row.ExpirationDays, row.ExpiredObjectDeleteMarker = rule.Expiration.Date, rule.Expiration.Days, rule.Expiration.ExpiredObjectDeleteMarker
		}
		if rule.NoncurrentExpiration != nil {
			row.NoncurrentExpirationDays = new(rule.NoncurrentExpiration.Days)
			row.NoncurrentExpirationNewerVersions = rule.NoncurrentExpiration.NewerNoncurrentVersions
		}
		if err := w.q.PutBucketLifecycleRule(w.ctx, row); err != nil {
			return err
		}
		for tagPosition, tag := range rule.Filter.Tags {
			if err := w.q.PutBucketLifecycleTag(w.ctx, sqlcgen.PutBucketLifecycleTagParams{
				Partition: key.Partition, BucketName: key.Name, RulePosition: int64(position), Position: int64(tagPosition), Key: tag.Key, Value: tag.Value,
			}); err != nil {
				return err
			}
		}
		for transitionPosition, transition := range rule.Transitions {
			if err := w.q.PutBucketLifecycleTransition(w.ctx, sqlcgen.PutBucketLifecycleTransitionParams{
				Partition: key.Partition, BucketName: key.Name, RulePosition: int64(position), Position: int64(transitionPosition),
				Date: transition.Date, Days: transition.Days, StorageClass: transition.StorageClass,
			}); err != nil {
				return err
			}
		}
		for transitionPosition, transition := range rule.NoncurrentTransitions {
			if err := w.q.PutBucketLifecycleTransition(w.ctx, sqlcgen.PutBucketLifecycleTransitionParams{
				Partition: key.Partition, BucketName: key.Name, RulePosition: int64(position), Position: int64(transitionPosition), Noncurrent: true,
				Days: new(transition.Days), StorageClass: transition.StorageClass, NewerNoncurrentVersions: transition.NewerNoncurrentVersions,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w writer) TransitionObject(key domain.ObjectVersionKey, storageClass string) (int64, error) {
	sequence, err := w.q.NextObjectSequence(w.ctx)
	if err != nil {
		return 0, err
	}
	changed, err := w.q.TransitionObject(w.ctx, sqlcgen.TransitionObjectParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name, VersionID: key.VersionID,
		StorageClass: storageClass, Sequence: sequence,
	})
	if err != nil {
		return 0, err
	}
	if changed == 0 {
		return 0, domain.ErrNotFound
	}
	return sequence, nil
}
