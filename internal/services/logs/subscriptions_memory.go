package logs

import (
	"bytes"
	"cmp"
	"errors"
	"slices"
	"strings"

	"stackd/internal/scheduler"
)

func cloneSubscription(v SubscriptionRecord) SubscriptionRecord {
	v.EmitSystemFields = slices.Clone(v.EmitSystemFields)
	return v
}
func (r memoryReader) Subscription(k SubscriptionKey) (SubscriptionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SubscriptionRecord{}, err
	}
	v, ok := r.state.subscriptions[k]
	if !ok {
		return v, ErrNotFound
	}
	return cloneSubscription(v), nil
}
func (r memoryReader) Subscriptions(q SubscriptionQuery) ([]SubscriptionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []SubscriptionRecord{}
	for k, v := range r.state.subscriptions {
		if k.GroupID == q.GroupID && k.Name > q.After && strings.HasPrefix(k.Name, q.Prefix) {
			out = append(out, cloneSubscription(v))
		}
	}
	slices.SortFunc(out, func(a, b SubscriptionRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func (w memoryWriter) PutSubscription(v SubscriptionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	found := false
	for _, g := range w.state.groups {
		if g.ID == v.Key.GroupID {
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	if old, ok := w.state.subscriptions[v.Key]; ok && old.ID != v.ID {
		if err := w.DeleteSubscription(v.Key); err != nil {
			return err
		}
	}
	w.state.subscriptions[v.Key] = cloneSubscription(v)
	return nil
}
func (w memoryWriter) DeleteSubscription(k SubscriptionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v, ok := w.state.subscriptions[k]
	if !ok {
		return nil
	}
	delete(w.state.subscriptions, k)
	for id, d := range w.state.deliveries {
		if d.SubscriptionID == v.ID {
			delete(w.state.deliveries, id)
		}
	}
	return nil
}
func (r memoryReader) SubscriptionDelivery(id string) (SubscriptionDelivery, error) {
	if err := r.tx.Check(false); err != nil {
		return SubscriptionDelivery{}, err
	}
	v, ok := r.state.deliveries[id]
	if !ok {
		return v, ErrNotFound
	}
	v.Payload = bytes.Clone(v.Payload)
	return v, nil
}
func (r memoryReader) NextSubscriptionDelivery() (scheduler.Job, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return scheduler.Job{}, false, err
	}
	var next scheduler.Job
	found := false
	for _, d := range r.state.deliveries {
		job := scheduler.Job{Key: d.ID, Version: d.Version, Due: d.Due}
		if !found || scheduler.Compare(job, next) < 0 {
			next, found = job, true
		}
	}
	return next, found, nil
}
func (w memoryWriter) PutSubscriptionDelivery(v SubscriptionDelivery) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	sub, ok := w.state.subscriptions[v.Key]
	if !ok || sub.ID != v.SubscriptionID {
		return ErrNotFound
	}
	if old, ok := w.state.deliveries[v.ID]; ok {
		if old.SubscriptionID != v.SubscriptionID {
			return errors.New("subscription delivery identity is immutable")
		}
		old.Due, old.Version, old.Attempts = v.Due, v.Version, v.Attempts
		w.state.deliveries[v.ID] = old
	} else {
		v.Payload = bytes.Clone(v.Payload)
		w.state.deliveries[v.ID] = v
	}
	return nil
}
func (w memoryWriter) DeleteSubscriptionDelivery(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.deliveries, id)
	return nil
}
