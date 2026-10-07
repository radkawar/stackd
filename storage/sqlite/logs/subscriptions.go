package logs

import (
	"database/sql"
	"errors"
	"time"

	"stackd/internal/scheduler"
	domain "stackd/storage/logs"
	"stackd/storage/sqlite/logs/internal/sqlcgen"
)

func (r reader) subscription(v sqlcgen.LogsSubscription) (domain.SubscriptionRecord, error) {
	fields, err := r.q.SubscriptionSystemFields(r.ctx, v.ID)
	return domain.SubscriptionRecord{CFNOwner: v.CfnOwner, Key: domain.SubscriptionKey{GroupID: v.GroupID, Name: v.Name}, ID: v.ID, Pattern: v.Pattern, DestinationARN: v.DestinationArn, RoleARN: v.RoleArn, TargetARN: v.TargetArn, RoleSourceARN: v.RoleSourceArn, SenderRoleARN: v.SenderRoleArn, ApplyOnTransformedLogs: v.ApplyOnTransformedLogs != 0, Distribution: v.Distribution, FieldSelection: v.FieldSelection, Created: v.Created, DisabledUntil: time.UnixMilli(v.DisabledUntil).UTC(), EmitSystemFields: fields}, err
}
func (r reader) Subscription(k domain.SubscriptionKey) (domain.SubscriptionRecord, error) {
	v, err := r.q.GetSubscription(r.ctx, sqlcgen.GetSubscriptionParams{GroupID: k.GroupID, Name: k.Name})
	if err != nil {
		return domain.SubscriptionRecord{}, notFound(err)
	}
	return r.subscription(v)
}
func (r reader) Subscriptions(q domain.SubscriptionQuery) ([]domain.SubscriptionRecord, error) {
	rows, err := r.q.ListSubscriptions(r.ctx, sqlcgen.ListSubscriptionsParams{GroupID: q.GroupID, AfterName: q.After, Prefix: q.Prefix, PageLimit: int64(q.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SubscriptionRecord, 0, len(rows))
	for _, v := range rows {
		sub, err := r.subscription(v)
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, nil
}
func (w writer) PutSubscription(v domain.SubscriptionRecord) error {
	old, err := w.q.GetSubscription(w.ctx, sqlcgen.GetSubscriptionParams{GroupID: v.Key.GroupID, Name: v.Key.Name})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && old.ID != v.ID {
		if err := w.DeleteSubscription(v.Key); err != nil {
			return err
		}
	}
	transformed := int64(0)
	if v.ApplyOnTransformedLogs {
		transformed = 1
	}
	if err := w.q.PutSubscription(w.ctx, sqlcgen.PutSubscriptionParams{CfnOwner: v.CFNOwner, GroupID: v.Key.GroupID, Name: v.Key.Name, ID: v.ID, Pattern: v.Pattern, DestinationArn: v.DestinationARN, RoleArn: v.RoleARN, TargetArn: v.TargetARN, RoleSourceArn: v.RoleSourceARN, SenderRoleArn: v.SenderRoleARN, ApplyOnTransformedLogs: transformed, Distribution: v.Distribution, FieldSelection: v.FieldSelection, Created: v.Created, DisabledUntil: v.DisabledUntil.UnixMilli()}); err != nil {
		return err
	}
	if err := w.q.DeleteSubscriptionSystemFields(w.ctx, v.ID); err != nil {
		return err
	}
	for i, field := range v.EmitSystemFields {
		if err := w.q.PutSubscriptionSystemField(w.ctx, sqlcgen.PutSubscriptionSystemFieldParams{SubscriptionID: v.ID, Ordinal: int64(i), Field: field}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteSubscription(k domain.SubscriptionKey) error {
	return w.q.DeleteSubscription(w.ctx, sqlcgen.DeleteSubscriptionParams{GroupID: k.GroupID, Name: k.Name})
}
func (r reader) SubscriptionDelivery(id string) (domain.SubscriptionDelivery, error) {
	v, err := r.q.GetSubscriptionDelivery(r.ctx, id)
	if err != nil {
		return domain.SubscriptionDelivery{}, notFound(err)
	}
	return domain.SubscriptionDelivery{ID: v.ID, SubscriptionID: v.SubscriptionID, Key: domain.SubscriptionKey{GroupID: v.GroupID, Name: v.FilterName}, Group: domain.GroupKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.GroupName}, DestinationARN: v.DestinationArn, RoleARN: v.RoleArn, TargetARN: v.TargetArn, RoleSourceARN: v.RoleSourceArn, PartitionKey: v.PartitionKey, ParentEventID: v.ParentEventID, RequestID: v.RequestID, Payload: v.Payload, Due: time.UnixMilli(v.Due).UTC(), Expires: time.UnixMilli(v.Expires).UTC(), Version: uint64(v.Version), Attempts: int(v.Attempts)}, nil
}
func (r reader) NextSubscriptionDelivery() (scheduler.Job, bool, error) {
	v, err := r.q.NextSubscriptionDelivery(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return scheduler.Job{}, false, nil
	}
	return scheduler.Job{Key: v.ID, Version: uint64(v.Version), Due: time.UnixMilli(v.Due).UTC()}, err == nil, err
}
func (w writer) PutSubscriptionDelivery(v domain.SubscriptionDelivery) error {
	sub, err := w.q.GetSubscription(w.ctx, sqlcgen.GetSubscriptionParams{GroupID: v.Key.GroupID, Name: v.Key.Name})
	if err != nil {
		return notFound(err)
	}
	if sub.ID != v.SubscriptionID {
		return domain.ErrNotFound
	}
	return w.q.PutSubscriptionDelivery(w.ctx, sqlcgen.PutSubscriptionDeliveryParams{ID: v.ID, SubscriptionID: v.SubscriptionID, GroupID: v.Key.GroupID, FilterName: v.Key.Name, Partition: v.Group.Partition, AccountID: v.Group.AccountID, Region: v.Group.Region, GroupName: v.Group.Name, DestinationArn: v.DestinationARN, RoleArn: v.RoleARN, TargetArn: v.TargetARN, RoleSourceArn: v.RoleSourceARN, PartitionKey: v.PartitionKey, ParentEventID: v.ParentEventID, RequestID: v.RequestID, Payload: v.Payload, Due: v.Due.UnixMilli(), Expires: v.Expires.UnixMilli(), Version: int64(v.Version), Attempts: int64(v.Attempts)})
}
func (w writer) DeleteSubscriptionDelivery(id string) error {
	return w.q.DeleteSubscriptionDelivery(w.ctx, id)
}
