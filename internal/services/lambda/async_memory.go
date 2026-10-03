package lambda

import (
	"slices"
	"stackd/internal/scheduler"
	"stackd/storage/memory"
)

func cloneEventInvokeConfig(v EventInvokeConfig) EventInvokeConfig {
	if v.AppliesAt != nil {
		due := *v.AppliesAt
		v.AppliesAt = &due
	}
	return v
}
func (r memoryReader) EventInvokeConfig(k FunctionReference) (v EventInvokeConfig, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.configs.View(r.Context(), func(rows *map[FunctionReference]EventInvokeConfig, _ *memory.Transaction) error {
		var ok bool
		v, ok = (*rows)[k]
		if !ok {
			return ErrNotFound
		}
		v = cloneEventInvokeConfig(v)
		return nil
	})
	return
}
func (r memoryReader) NextEventInvokeConfigChange() (job scheduler.Job, found bool, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.configs.View(r.Context(), func(rows *map[FunctionReference]EventInvokeConfig, _ *memory.Transaction) error {
		for _, v := range *rows {
			if v.AppliesAt == nil {
				continue
			}
			candidate := scheduler.Job{Key: v.Key.ARN(), Version: v.Version, Due: *v.AppliesAt}
			if !found || scheduler.Compare(candidate, job) < 0 {
				job, found = candidate, true
			}
		}
		return nil
	})
	return
}
func (w memoryWriter) PutEventInvokeConfig(v EventInvokeConfig) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, exists := (*w.state)[deploymentKey{FunctionKey: v.Key.FunctionKey}]; !exists {
		return ErrNotFound
	}
	return w.repository.configs.Update(w.Context(), func(rows *map[FunctionReference]EventInvokeConfig, _ *memory.Transaction) error {
		(*rows)[v.Key] = cloneEventInvokeConfig(v)
		return nil
	})
}
func (w memoryWriter) DeleteEventInvokeConfig(k FunctionReference) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.configs.Update(w.Context(), func(rows *map[FunctionReference]EventInvokeConfig, _ *memory.Transaction) error {
		delete(*rows, k)
		return nil
	})
}
func cloneInvocation(v InvocationRecord) InvocationRecord {
	v.Payload = slices.Clone(v.Payload)
	v.ResponsePayload = slices.Clone(v.ResponsePayload)
	return v
}
func (r memoryReader) Invocation(id string) (v InvocationRecord, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.invocations.View(r.Context(), func(rows *map[string]InvocationRecord, _ *memory.Transaction) error {
		var ok bool
		v, ok = (*rows)[id]
		if !ok {
			return ErrNotFound
		}
		v = cloneInvocation(v)
		return nil
	})
	return
}
func invocationJob(v InvocationRecord) scheduler.Job {
	return scheduler.Job{Key: v.ID, Version: v.Version, Due: v.Due}
}
func (r memoryReader) NextInvocation() (v scheduler.Job, found bool, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.invocations.View(r.Context(), func(rows *map[string]InvocationRecord, _ *memory.Transaction) error {
		for _, row := range *rows {
			if row.State != "queued" {
				continue
			}
			if candidate := invocationJob(row); !found || scheduler.Compare(candidate, v) < 0 {
				v, found = candidate, true
			}
		}
		return nil
	})
	return
}
func (r memoryReader) InFlightInvocations() (out []InvocationRecord, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.invocations.View(r.Context(), func(rows *map[string]InvocationRecord, _ *memory.Transaction) error {
		for _, v := range *rows {
			if v.State == "in-flight" {
				out = append(out, cloneInvocation(v))
			}
		}
		slices.SortFunc(out, func(a, b InvocationRecord) int { return scheduler.Compare(invocationJob(a), invocationJob(b)) })
		return nil
	})
	return
}
func (w memoryWriter) PutInvocation(v InvocationRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.invocations.Update(w.Context(), func(rows *map[string]InvocationRecord, _ *memory.Transaction) error {
		(*rows)[v.ID] = cloneInvocation(v)
		return nil
	})
}
func (w memoryWriter) DeleteInvocation(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if err := w.repository.outcomes.Update(w.Context(), func(rows *map[string]OutcomeDeliveryRecord, _ *memory.Transaction) error {
		for routeID, row := range *rows {
			if row.InvocationID == id {
				delete(*rows, routeID)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return w.repository.invocations.Update(w.Context(), func(rows *map[string]InvocationRecord, _ *memory.Transaction) error { delete(*rows, id); return nil })
}

func (w memoryWriter) detachFunctionInvocations(key FunctionKey) error {
	return w.repository.invocations.Update(w.Context(), func(rows *map[string]InvocationRecord, _ *memory.Transaction) error {
		for id, invocation := range *rows {
			if invocation.Key == key && invocation.State != "completed" {
				invocation.SettingsDetached = true
				(*rows)[id] = invocation
			}
		}
		return nil
	})
}

func (w memoryWriter) ReattachInvocationSettings(ref FunctionReference) error {
	return w.repository.invocations.Update(w.Context(), func(rows *map[string]InvocationRecord, _ *memory.Transaction) error {
		for id, invocation := range *rows {
			if invocation.State != "completed" && eventInvokeConfigReference(invocation.Reference()) == ref {
				invocation.SettingsDetached = false
				(*rows)[id] = invocation
			}
		}
		return nil
	})
}
