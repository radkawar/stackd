package lambda

import (
	"stackd/internal/scheduler"
	"stackd/storage/memory"
)

func (r memoryReader) OutcomeDelivery(id string) (v OutcomeDeliveryRecord, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.outcomes.View(r.Context(), func(rows *map[string]OutcomeDeliveryRecord, _ *memory.Transaction) error {
		var ok bool
		v, ok = (*rows)[id]
		if !ok {
			return ErrNotFound
		}
		return nil
	})
	return
}

func (r memoryReader) NextOutcomeDelivery() (job scheduler.Job, found bool, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.outcomes.View(r.Context(), func(routes *map[string]OutcomeDeliveryRecord, _ *memory.Transaction) error {
		return r.repository.invocations.View(r.Context(), func(invocations *map[string]InvocationRecord, _ *memory.Transaction) error {
			for _, route := range *routes {
				parent, ok := (*invocations)[route.InvocationID]
				if !ok || parent.State != "completed" {
					continue
				}
				candidate := scheduler.Job{Key: route.ID, Due: parent.Completed}
				if !found || scheduler.Compare(candidate, job) < 0 {
					job, found = candidate, true
				}
			}
			return nil
		})
	})
	return
}

func (w memoryWriter) PutOutcomeDelivery(v OutcomeDeliveryRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.outcomes.Update(w.Context(), func(rows *map[string]OutcomeDeliveryRecord, _ *memory.Transaction) error {
		if _, exists := (*rows)[v.ID]; exists {
			return nil
		}
		if err := w.repository.invocations.View(w.Context(), func(invocations *map[string]InvocationRecord, _ *memory.Transaction) error {
			if _, exists := (*invocations)[v.InvocationID]; !exists {
				return ErrNotFound
			}
			return nil
		}); err != nil {
			return err
		}
		(*rows)[v.ID] = v
		return nil
	})
}

func (w memoryWriter) DeleteOutcomeDelivery(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.outcomes.Update(w.Context(), func(rows *map[string]OutcomeDeliveryRecord, _ *memory.Transaction) error {
		route, exists := (*rows)[id]
		if !exists {
			return nil
		}
		delete(*rows, id)
		for _, other := range *rows {
			if other.InvocationID == route.InvocationID {
				return nil
			}
		}
		return w.repository.invocations.Update(w.Context(), func(invocations *map[string]InvocationRecord, _ *memory.Transaction) error {
			if parent, exists := (*invocations)[route.InvocationID]; exists && parent.State == "completed" {
				delete(*invocations, route.InvocationID)
			}
			return nil
		})
	})
}
