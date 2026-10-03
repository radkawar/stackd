package s3

import (
	"slices"

	"stackd/internal/scheduler"
	"stackd/storage/memory"
)

func cloneNotificationConfiguration(v NotificationConfiguration) NotificationConfiguration {
	v.Rules = slices.Clone(v.Rules)
	for i := range v.Rules {
		v.Rules[i].Events = slices.Clone(v.Rules[i].Events)
		v.Rules[i].Filters = slices.Clone(v.Rules[i].Filters)
	}
	return v
}

func cloneNotificationState(v NotificationState) NotificationState {
	v.Desired = cloneNotificationConfiguration(v.Desired)
	v.Applied = cloneNotificationConfiguration(v.Applied)
	if v.ApplyAt != nil {
		at := *v.ApplyAt
		v.ApplyAt = &at
	}
	return v
}

func (r memoryReader) NotificationState(key BucketKey) (NotificationState, error) {
	var out NotificationState
	err := r.repository.notifications.View(r.Context(), func(state *map[BucketKey]NotificationState, _ *memory.Transaction) error {
		v, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		out = cloneNotificationState(v)
		return nil
	})
	return out, err
}

func (w memoryWriter) PutNotificationState(v NotificationState) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := (*w.state)[v.Bucket]; !ok {
		return ErrNotFound
	}
	return w.repository.notifications.Update(w.Context(), func(state *map[BucketKey]NotificationState, _ *memory.Transaction) error {
		(*state)[v.Bucket] = cloneNotificationState(v)
		return nil
	})
}

func (r memoryReader) NextNotificationChange() (scheduler.Job, bool, error) {
	var out scheduler.Job
	found := false
	err := r.repository.notifications.View(r.Context(), func(state *map[BucketKey]NotificationState, _ *memory.Transaction) error {
		for key, v := range *state {
			if v.ApplyAt == nil {
				continue
			}
			id := key.Partition + ":" + key.Name
			if !found || v.ApplyAt.Before(out.Due) || (v.ApplyAt.Equal(out.Due) && id < out.Key) {
				out = scheduler.Job{Key: id, Version: v.Version, Due: *v.ApplyAt}
				found = true
			}
		}
		return nil
	})
	return out, found, err
}

func (r memoryReader) NotificationDelivery(id string) (NotificationDelivery, error) {
	var out NotificationDelivery
	err := r.repository.deliveries.View(r.Context(), func(state *map[string]NotificationDelivery, _ *memory.Transaction) error {
		var ok bool
		out, ok = (*state)[id]
		if !ok {
			return ErrNotFound
		}
		return nil
	})
	return out, err
}

func (w memoryWriter) PutNotificationDelivery(v NotificationDelivery) error {
	return w.repository.deliveries.Update(w.Context(), func(state *map[string]NotificationDelivery, _ *memory.Transaction) error {
		if current, ok := (*state)[v.ID]; ok {
			current.Due, current.Attempts, current.Version = v.Due, v.Attempts, v.Version
			v = current
		}
		(*state)[v.ID] = v
		return nil
	})
}

func (w memoryWriter) DeleteNotificationDelivery(id string) error {
	return w.repository.deliveries.Update(w.Context(), func(state *map[string]NotificationDelivery, _ *memory.Transaction) error {
		delete(*state, id)
		return nil
	})
}

func (r memoryReader) NextNotificationDelivery() (scheduler.Job, bool, error) {
	var out scheduler.Job
	found := false
	err := r.repository.deliveries.View(r.Context(), func(state *map[string]NotificationDelivery, _ *memory.Transaction) error {
		for id, v := range *state {
			if !found || v.Due.Before(out.Due) || (v.Due.Equal(out.Due) && id < out.Key) {
				out = scheduler.Job{Key: id, Version: v.Version, Due: v.Due}
				found = true
			}
		}
		return nil
	})
	return out, found, err
}
