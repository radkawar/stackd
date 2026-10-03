package s3

import (
	"slices"

	"stackd/internal/scheduler"
	"stackd/storage/memory"
)

func cloneAccessLogDelivery(delivery AccessLogDelivery) AccessLogDelivery {
	delivery.Destination.Grants = slices.Clone(delivery.Destination.Grants)
	return delivery
}

func (r memoryReader) AccessLogDelivery(id string) (AccessLogDelivery, error) {
	var out AccessLogDelivery
	err := r.repository.accessLogs.View(r.Context(), func(state *map[string]AccessLogDelivery, _ *memory.Transaction) error {
		delivery, ok := (*state)[id]
		if !ok {
			return ErrNotFound
		}
		out = cloneAccessLogDelivery(delivery)
		return nil
	})
	return out, err
}

func (r memoryReader) NextAccessLogDelivery() (scheduler.Job, bool, error) {
	var out scheduler.Job
	found := false
	err := r.repository.accessLogs.View(r.Context(), func(state *map[string]AccessLogDelivery, _ *memory.Transaction) error {
		for _, delivery := range *state {
			if !found || delivery.Due.Before(out.Due) || (delivery.Due.Equal(out.Due) && delivery.ID < out.Key) {
				out = scheduler.Job{Key: delivery.ID, Due: delivery.Due}
				found = true
			}
		}
		return nil
	})
	return out, found, err
}

func (w memoryWriter) PutAccessLogDelivery(delivery AccessLogDelivery) error {
	return w.repository.accessLogs.Update(w.Context(), func(state *map[string]AccessLogDelivery, _ *memory.Transaction) error {
		if current, ok := (*state)[delivery.ID]; ok {
			current.Due = delivery.Due
			(*state)[delivery.ID] = current
		} else {
			(*state)[delivery.ID] = cloneAccessLogDelivery(delivery)
		}
		return nil
	})
}

func (w memoryWriter) DeleteAccessLogDelivery(id string) error {
	return w.repository.accessLogs.Update(w.Context(), func(state *map[string]AccessLogDelivery, _ *memory.Transaction) error {
		delete(*state, id)
		return nil
	})
}
