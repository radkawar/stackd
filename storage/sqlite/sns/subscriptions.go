package sns

import (
	"database/sql"
	"errors"
	"time"

	"stackd/internal/scheduler"
	domain "stackd/storage/sns"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/sns/internal/sqlcgen"
)

func (r reader) Subscription(k domain.SubscriptionKey) (domain.SubscriptionRecord, error) {
	v, err := r.q.GetSubscription(r.ctx, k.ARN())
	if err != nil {
		return domain.SubscriptionRecord{}, missing(err)
	}
	return subscription(v), nil
}

func (r reader) SubscriptionByEndpoint(topicID, protocol, endpoint string) (domain.SubscriptionRecord, error) {
	v, err := r.q.GetSubscriptionByEndpoint(r.ctx, sqlcgen.GetSubscriptionByEndpointParams{TopicID: topicID, Protocol: protocol, Endpoint: endpoint})
	if err != nil {
		return domain.SubscriptionRecord{}, missing(err)
	}
	return subscription(v), nil
}

func (r reader) Confirmation(token string) (domain.ConfirmationRecord, error) {
	v, err := r.q.GetConfirmation(r.ctx, token)
	if err != nil {
		return domain.ConfirmationRecord{}, missing(err)
	}
	return domain.ConfirmationRecord{Token: v.Token, Expires: v.Expires, Subscription: domain.SubscriptionKey{Topic: domain.TopicKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.TopicName}, ID: v.SubscriptionID}}, nil
}

func (w writer) PutConfirmation(v domain.ConfirmationRecord) error {
	k := v.Subscription.Topic
	return w.q.PutConfirmation(w.ctx, sqlcgen.PutConfirmationParams{Token: v.Token, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TopicName: k.Name, SubscriptionID: v.Subscription.ID, Expires: v.Expires.UTC()})
}

func (w writer) DeleteExpiredConfirmations(now time.Time) error {
	return w.q.DeleteExpiredConfirmations(w.ctx, now.UTC())
}

func (r reader) SubscriptionsByTopic(q domain.TopicSubscriptionQuery) ([]domain.SubscriptionRecord, error) {
	k := q.Topic
	rows, err := r.q.ListSubscriptionsByTopic(r.ctx, sqlcgen.ListSubscriptionsByTopicParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TopicName: k.Name, TopicID: q.TopicID, AfterID: q.After, PageLimit: pageLimit(q.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SubscriptionRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, subscription(v))
	}
	return out, nil
}

func (r reader) SubscriptionsByOwner(q domain.OwnerSubscriptionQuery) ([]domain.SubscriptionRecord, error) {
	rows, err := r.q.ListSubscriptionsByOwner(r.ctx, sqlcgen.ListSubscriptionsByOwnerParams{Partition: q.Partition, Region: q.Region, Owner: q.AccountID, AfterArn: q.AfterARN, PageLimit: pageLimit(q.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SubscriptionRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, subscription(v))
	}
	return out, nil
}

func (r reader) SubscriptionCount(topicID string) (int64, error) {
	return r.q.CountSubscriptions(r.ctx, topicID)
}

func (r reader) FilterPolicyCount(scope domain.Scope, topicID string) (int64, error) {
	if topicID != "" {
		return r.q.CountTopicFilterPolicies(r.ctx, sqlcgen.CountTopicFilterPoliciesParams{Partition: scope.Partition, Region: scope.Region, TopicID: topicID})
	}
	return r.q.CountOwnerFilterPolicies(r.ctx, sqlcgen.CountOwnerFilterPoliciesParams{Partition: scope.Partition, Region: scope.Region, Owner: scope.AccountID})
}

func (r reader) NextSubscriptionDeletion() (scheduler.Job, bool, error) {
	v, err := r.q.NextSubscriptionDeletion(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: v.Arn, Version: uint64(v.Version), Due: *v.DeletionDue}, true, nil
}

func subscription(v sqlcgen.SnsSubscription) domain.SubscriptionRecord {
	return domain.SubscriptionRecord{
		Key:     domain.SubscriptionKey{Topic: domain.TopicKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.TopicName}, ID: v.ID},
		TopicID: v.TopicID, Owner: v.Owner, PrincipalARN: v.PrincipalArn, Protocol: v.Protocol, Endpoint: v.Endpoint,
		Created: v.Created, Version: uint64(v.Version), RawMessageDelivery: v.RawMessageDelivery,
		FilterPolicy: v.FilterPolicy, FilterScope: v.FilterScope, RedriveARN: v.RedriveArn, DeletionDue: v.DeletionDue,
		State: v.State, ConfirmationAuthenticated: v.ConfirmationAuthenticated, AuthenticateOnUnsubscribe: v.AuthenticateOnUnsubscribe, SubscriptionRoleARN: v.SubscriptionRoleArn, DeliveryPolicy: v.DeliveryPolicy, NextHTTPDelivery: v.NextHttpDelivery,
		Replay: domain.ReplayRecord{
			Policy: v.ReplayPolicy, Status: v.ReplayStatus,
			Start: v.ReplayStart, End: v.ReplayEnd, Due: v.ReplayDue, Cursor: uint64(v.ReplayCursor), Paused: v.ReplayPaused,
		},
	}
}

func (w writer) PutSubscription(v domain.SubscriptionRecord) error {
	k := v.Key.Topic
	return w.q.PutSubscription(w.ctx, sqlcgen.PutSubscriptionParams{
		Arn: v.Key.ARN(), Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TopicName: k.Name, ID: v.Key.ID,
		TopicID: v.TopicID, Owner: v.Owner, PrincipalArn: v.PrincipalARN, Protocol: v.Protocol, Endpoint: v.Endpoint,
		Created: v.Created.UTC(), Version: sqlite.Uint64(v.Version), RawMessageDelivery: v.RawMessageDelivery,
		FilterPolicy: v.FilterPolicy, FilterScope: v.FilterScope, RedriveArn: v.RedriveARN, DeletionDue: utcPointer(v.DeletionDue),
		State: v.State, ConfirmationAuthenticated: v.ConfirmationAuthenticated, AuthenticateOnUnsubscribe: v.AuthenticateOnUnsubscribe, SubscriptionRoleArn: v.SubscriptionRoleARN, DeliveryPolicy: v.DeliveryPolicy, NextHttpDelivery: v.NextHTTPDelivery.UTC(),
		ReplayPolicy: v.Replay.Policy, ReplayStatus: v.Replay.Status,
		ReplayStart: v.Replay.Start.UTC(), ReplayEnd: v.Replay.End.UTC(), ReplayDue: v.Replay.Due.UTC(),
		ReplayCursor: sqlite.Uint64(v.Replay.Cursor), ReplayPaused: v.Replay.Paused,
	})
}

func (w writer) OrphanTopicSubscriptions(topicID string, due time.Time) error {
	rows, err := w.q.ListTopicSubscriptionVersions(w.ctx, topicID)
	if err != nil {
		return err
	}
	due = due.UTC()
	for _, v := range rows {
		// Increment in Go: SQLite INTEGER arithmetic cannot represent the full uint64 domain.
		if err := w.q.SetSubscriptionDeletion(w.ctx, sqlcgen.SetSubscriptionDeletionParams{DeletionDue: &due, Version: v.Version + 1, Arn: v.Arn}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteSubscription(k domain.SubscriptionKey) error {
	messages, err := w.q.DeleteSubscriptionDeliveries(w.ctx, k.ARN())
	if err != nil {
		return err
	}
	if err := w.q.DeleteSubscription(w.ctx, k.ARN()); err != nil {
		return err
	}
	for _, message := range messages {
		if err := w.q.CollectMessage(w.ctx, sqlcgen.CollectMessageParams(message)); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteSubscriptionNotifications(k domain.SubscriptionKey) error {
	messages, err := w.q.DeleteSubscriptionNotifications(w.ctx, k.ARN())
	if err != nil {
		return err
	}
	for _, message := range messages {
		if err := w.q.CollectMessage(w.ctx, sqlcgen.CollectMessageParams(message)); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) NextReplay() (domain.SubscriptionRecord, bool, error) {
	v, err := r.q.NextReplay(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.SubscriptionRecord{}, false, nil
	}
	if err != nil {
		return domain.SubscriptionRecord{}, false, err
	}
	return subscription(v), true, nil
}
