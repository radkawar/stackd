package s3

import (
	"database/sql"
	"errors"
	"time"

	"stackd/internal/scheduler"
	domain "stackd/storage/s3"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) NotificationState(key domain.BucketKey) (domain.NotificationState, error) {
	row, err := r.q.GetNotificationState(r.ctx, sqlcgen.GetNotificationStateParams{Partition: key.Partition, BucketName: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.NotificationState{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.NotificationState{}, err
	}
	out := domain.NotificationState{Bucket: key, ApplyAt: row.ApplyAt, Version: uint64(row.Version)}
	out.Desired.EventBridge = row.DesiredEventBridge
	out.Applied.EventBridge = row.AppliedEventBridge
	out.Desired.Rules, err = r.notificationRules(key, false)
	if err != nil {
		return domain.NotificationState{}, err
	}
	out.Applied.Rules, err = r.notificationRules(key, true)
	if err != nil {
		return domain.NotificationState{}, err
	}
	return out, nil
}

func (r reader) notificationRules(key domain.BucketKey, applied bool) ([]domain.NotificationRule, error) {
	rows, err := r.q.ListNotificationRules(r.ctx, sqlcgen.ListNotificationRulesParams{Partition: key.Partition, BucketName: key.Name, Applied: applied})
	if err != nil {
		return nil, err
	}
	out := make([]domain.NotificationRule, 0, len(rows))
	for _, row := range rows {
		events, err := r.q.ListNotificationEvents(r.ctx, sqlcgen.ListNotificationEventsParams{
			Partition: key.Partition, BucketName: key.Name, Applied: applied, RulePosition: row.Position,
		})
		if err != nil {
			return nil, err
		}
		filters, err := r.q.ListNotificationFilters(r.ctx, sqlcgen.ListNotificationFiltersParams{
			Partition: key.Partition, BucketName: key.Name, Applied: applied, RulePosition: row.Position,
		})
		if err != nil {
			return nil, err
		}
		rule := domain.NotificationRule{
			ID: row.ID, Protocol: domain.NotificationProtocol(row.Protocol), DestinationARN: row.DestinationArn,
			Events: events, Filters: make([]domain.NotificationFilter, 0, len(filters)),
		}
		for _, filter := range filters {
			rule.Filters = append(rule.Filters, domain.NotificationFilter{Name: filter.Name, Value: filter.Value})
		}
		out = append(out, rule)
	}
	return out, nil
}

func (r reader) NextNotificationChange() (scheduler.Job, bool, error) {
	row, err := r.q.NextNotificationChange(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: row.Partition + ":" + row.BucketName, Due: *row.ApplyAt, Version: uint64(row.Version)}, true, nil
}

func (w writer) PutNotificationState(state domain.NotificationState) error {
	var applyAt *time.Time
	if state.ApplyAt != nil {
		instant := state.ApplyAt.UTC()
		applyAt = &instant
	}
	if err := w.q.PutNotificationState(w.ctx, sqlcgen.PutNotificationStateParams{
		Partition: state.Bucket.Partition, BucketName: state.Bucket.Name,
		DesiredEventBridge: state.Desired.EventBridge, AppliedEventBridge: state.Applied.EventBridge,
		ApplyAt: applyAt, Version: sqlite.Uint64(state.Version),
	}); err != nil {
		return err
	}
	if err := w.q.DeleteNotificationRules(w.ctx, sqlcgen.DeleteNotificationRulesParams{Partition: state.Bucket.Partition, BucketName: state.Bucket.Name}); err != nil {
		return err
	}
	if err := w.putNotificationRules(state.Bucket, false, state.Desired.Rules); err != nil {
		return err
	}
	return w.putNotificationRules(state.Bucket, true, state.Applied.Rules)
}

func (w writer) putNotificationRules(key domain.BucketKey, applied bool, rules []domain.NotificationRule) error {
	for i, rule := range rules {
		if err := w.q.PutNotificationRule(w.ctx, sqlcgen.PutNotificationRuleParams{
			Partition: key.Partition, BucketName: key.Name, Applied: applied, Position: int64(i),
			ID: rule.ID, Protocol: string(rule.Protocol), DestinationArn: rule.DestinationARN,
		}); err != nil {
			return err
		}
		for j, event := range rule.Events {
			if err := w.q.PutNotificationEvent(w.ctx, sqlcgen.PutNotificationEventParams{
				Partition: key.Partition, BucketName: key.Name, Applied: applied, RulePosition: int64(i), Position: int64(j), Event: event,
			}); err != nil {
				return err
			}
		}
		for j, filter := range rule.Filters {
			if err := w.q.PutNotificationFilter(w.ctx, sqlcgen.PutNotificationFilterParams{
				Partition: key.Partition, BucketName: key.Name, Applied: applied, RulePosition: int64(i), Position: int64(j),
				Name: filter.Name, Value: filter.Value,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r reader) NotificationDelivery(id string) (domain.NotificationDelivery, error) {
	row, err := r.q.GetNotificationDelivery(r.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.NotificationDelivery{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.NotificationDelivery{}, err
	}
	return domain.NotificationDelivery{
		ID: row.ID, Bucket: domain.BucketKey{Partition: row.Partition, Name: row.BucketName},
		AccountID: row.AccountID, Region: row.Region, Protocol: domain.NotificationProtocol(row.Protocol),
		DestinationARN: row.DestinationArn, Payload: row.Payload, RequestID: row.RequestID, ParentEventID: row.ParentEventID,
		Due: row.Due, Attempts: int(row.Attempts), Version: uint64(row.Version),
	}, nil
}

func (r reader) NextNotificationDelivery() (scheduler.Job, bool, error) {
	row, err := r.q.NextNotificationDelivery(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: row.ID, Due: row.Due, Version: uint64(row.Version)}, true, nil
}

func (w writer) PutNotificationDelivery(delivery domain.NotificationDelivery) error {
	return w.q.PutNotificationDelivery(w.ctx, sqlcgen.PutNotificationDeliveryParams{
		ID: delivery.ID, Partition: delivery.Bucket.Partition, BucketName: delivery.Bucket.Name,
		AccountID: delivery.AccountID, Region: delivery.Region, Protocol: string(delivery.Protocol),
		DestinationArn: delivery.DestinationARN, Payload: delivery.Payload, RequestID: delivery.RequestID, ParentEventID: delivery.ParentEventID,
		Due: delivery.Due.UTC(), Attempts: int64(delivery.Attempts), Version: sqlite.Uint64(delivery.Version),
	})
}

func (w writer) DeleteNotificationDelivery(id string) error {
	return w.q.DeleteNotificationDelivery(w.ctx, id)
}
