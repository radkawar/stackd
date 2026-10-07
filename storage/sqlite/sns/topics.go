package sns

import (
	"database/sql"
	"errors"
	"stackd/internal/authorization"
	domain "stackd/storage/sns"
	"stackd/storage/sqlite/sns/internal/sqlcgen"
	"time"
)

func (r reader) Topic(k domain.TopicKey) (domain.TopicRecord, error) {
	v, err := r.q.GetTopic(r.ctx, sqlcgen.GetTopicParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.TopicRecord{}, missing(err)
	}
	return r.topic(v)
}

func (r reader) Topics(q domain.TopicQuery) ([]domain.TopicRecord, error) {
	rows, err := r.q.ListTopics(r.ctx, sqlcgen.ListTopicsParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, AfterName: q.After, PageLimit: pageLimit(q.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.TopicRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.topic(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) TopicCount(scope domain.Scope) (int64, error) {
	return r.q.CountTopics(r.ctx, sqlcgen.CountTopicsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
}

func (r reader) topic(v sqlcgen.SnsTopic) (domain.TopicRecord, error) {
	tags, err := r.q.GetTopicTags(r.ctx, v.ID)
	if err != nil {
		return domain.TopicRecord{}, err
	}
	principals, err := r.q.GetTopicPrincipals(r.ctx, v.ID)
	if err != nil {
		return domain.TopicRecord{}, err
	}
	feedback, err := r.q.GetTopicFeedback(r.ctx, v.ID)
	if err != nil {
		return domain.TopicRecord{}, err
	}
	out := domain.TopicRecord{
		Key: domain.TopicKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name},
		ID:  v.ID, Created: v.Created, Updated: v.Updated, DisplayName: v.DisplayName,
		SignatureVersion: v.SignatureVersion, Policy: authorization.BoundPolicy{Document: v.Policy}, Tags: make(map[string]string, len(tags)),
		FIFO: v.Fifo, ContentBasedDeduplication: v.ContentBasedDeduplication, FifoThroughputScope: v.FifoThroughputScope, Sequence: uint64(v.Sequence),
		KmsMasterKeyID:  v.KmsMasterKeyID,
		DeliveryPolicy:  v.DeliveryPolicy,
		TracingConfig:   v.TracingConfig,
		CreationOwner:   domain.TopicCreationOwner{Owner: v.CfnTopicOwner, Token: v.CfnTopicToken},
		PolicyOwnership: domain.PolicyOwnership{Owner: v.CfnPolicyOwner, Identifier: v.CfnPolicyIdentifier, Type: v.CfnPolicyType},
	}
	archive, err := r.q.GetTopicArchive(r.ctx, v.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return domain.TopicRecord{}, err
	}
	if err == nil {
		out.Archive = &domain.ArchiveConfig{Policy: archive.Policy, RetentionDays: int32(archive.RetentionDays), Beginning: archive.Beginning, MetricDue: archive.MetricDue}
	}
	for _, tag := range tags {
		out.Tags[tag.Key] = tag.Value
	}
	if len(principals) > 0 {
		out.Policy.PrincipalIDs = make(map[string]string, len(principals))
		for _, principal := range principals {
			out.Policy.PrincipalIDs[principal.Arn] = principal.PrincipalID
		}
	}
	if len(feedback) != 0 {
		out.Feedback = make(map[string]domain.FeedbackConfig, len(feedback))
		for _, setting := range feedback {
			out.Feedback[setting.Protocol] = domain.FeedbackConfig{
				SuccessRoleARN: setting.SuccessRoleArn, FailureRoleARN: setting.FailureRoleArn,
				SuccessSampleRate: int(setting.SuccessSampleRate.Int64), SampleRateSet: setting.SuccessSampleRate.Valid,
			}
		}
	}
	return out, nil
}

func (w writer) PutTopic(v domain.TopicRecord) error {
	k := v.Key
	if err := w.q.PutTopic(w.ctx, sqlcgen.PutTopicParams{ID: v.ID, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Created: v.Created.UTC(), Updated: v.Updated.UTC(), DisplayName: v.DisplayName, SignatureVersion: v.SignatureVersion, Policy: v.Policy.Document, Fifo: v.FIFO, ContentBasedDeduplication: v.ContentBasedDeduplication, FifoThroughputScope: v.FifoThroughputScope, Sequence: int64(v.Sequence), KmsMasterKeyID: v.KmsMasterKeyID, DeliveryPolicy: v.DeliveryPolicy, TracingConfig: v.TracingConfig, CfnTopicOwner: v.CreationOwner.Owner, CfnTopicToken: v.CreationOwner.Token, CfnPolicyOwner: v.PolicyOwnership.Owner, CfnPolicyIdentifier: v.PolicyOwnership.Identifier, CfnPolicyType: v.PolicyOwnership.Type}); err != nil {
		return err
	}
	if err := w.q.DeleteTopicTags(w.ctx, v.ID); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutTopicTag(w.ctx, sqlcgen.PutTopicTagParams{TopicID: v.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteTopicPrincipals(w.ctx, v.ID); err != nil {
		return err
	}
	for arn, id := range v.Policy.PrincipalIDs {
		if err := w.q.PutTopicPrincipal(w.ctx, sqlcgen.PutTopicPrincipalParams{TopicID: v.ID, Arn: arn, PrincipalID: id}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteTopicFeedback(w.ctx, v.ID); err != nil {
		return err
	}
	for protocol, setting := range v.Feedback {
		if err := w.q.PutTopicFeedback(w.ctx, sqlcgen.PutTopicFeedbackParams{
			TopicID: v.ID, Protocol: protocol, SuccessRoleArn: setting.SuccessRoleARN, FailureRoleArn: setting.FailureRoleARN,
			SuccessSampleRate: sql.NullInt64{Int64: int64(setting.SuccessSampleRate), Valid: setting.SampleRateSet},
		}); err != nil {
			return err
		}
	}
	if v.Archive == nil {
		return w.q.DeleteTopicArchive(w.ctx, v.ID)
	}
	return w.q.PutTopicArchive(w.ctx, sqlcgen.PutTopicArchiveParams{
		TopicID: v.ID, Policy: v.Archive.Policy, RetentionDays: int64(v.Archive.RetentionDays),
		Beginning: v.Archive.Beginning.UTC(), MetricDue: v.Archive.MetricDue.UTC(),
	})
}

func (w writer) DeleteTopic(k domain.TopicKey) error {
	topic, err := w.q.GetTopic(w.ctx, sqlcgen.GetTopicParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := w.DeleteArchiveEntries(topic.ID); err != nil {
		return err
	}
	return w.q.DeleteTopic(w.ctx, sqlcgen.DeleteTopicParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}

func (r reader) Deduplication(k domain.DeduplicationKey) (domain.DeduplicationRecord, error) {
	v, err := r.q.GetDeduplication(r.ctx, sqlcgen.GetDeduplicationParams{TopicID: k.TopicID, MessageGroup: k.Group, DeduplicationID: k.ID})
	if err != nil {
		return domain.DeduplicationRecord{}, missing(err)
	}
	return domain.DeduplicationRecord{Key: k, MessageID: v.MessageID, SequenceNumber: v.SequenceNumber, Expires: v.Expires}, nil
}

func (w writer) PutDeduplication(v domain.DeduplicationRecord) error {
	return w.q.PutDeduplication(w.ctx, sqlcgen.PutDeduplicationParams{TopicID: v.Key.TopicID, MessageGroup: v.Key.Group, DeduplicationID: v.Key.ID, MessageID: v.MessageID, SequenceNumber: v.SequenceNumber, Expires: v.Expires.UTC()})
}

func (w writer) DeleteExpiredDeduplication(topicID string, now time.Time) error {
	return w.q.DeleteExpiredDeduplication(w.ctx, sqlcgen.DeleteExpiredDeduplicationParams{TopicID: topicID, Expires: now.UTC()})
}

func (w writer) NextTopicSequence(k domain.TopicKey) (uint64, error) {
	v, err := w.q.NextTopicSequence(w.ctx, sqlcgen.NextTopicSequenceParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	return uint64(v), missing(err)
}
