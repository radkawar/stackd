package lambda

import "stackd/storage/memory"

func (r memoryReader) FunctionConcurrency(key FunctionKey) (int32, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, false, err
	}
	var reserved int32
	var present bool
	err := r.repository.concurrency.View(r.Context(), func(state *map[FunctionKey]int32, _ *memory.Transaction) error {
		reserved, present = (*state)[key]
		return nil
	})
	return reserved, present, err
}

func (r memoryReader) AccountUsage(scope Scope) (AccountUsage, error) {
	if err := r.tx.Check(false); err != nil {
		return AccountUsage{}, err
	}
	var usage AccountUsage
	// COPY snapshots consume code storage; only current base functions count.
	for key, function := range *r.state {
		if !key.Pending && key.Scope == scope {
			if key.Version == 0 {
				usage.FunctionCount++
			}
			if function.Reference == nil {
				usage.TotalCodeSize += function.CodeSize
			}
		}
	}
	// Retained deployment bytes are not quota usage: only live COPY catalog
	// versions consume Lambda-managed layer storage.
	err := r.repository.layers.View(r.Context(), func(state *map[LayerVersionKey]LayerVersionRecord, _ *memory.Transaction) error {
		for key, layer := range *state {
			if key.Scope == scope && layer.Reference == nil {
				usage.TotalCodeSize += layer.CodeSize
			}
		}
		return nil
	})
	if err != nil {
		return AccountUsage{}, err
	}
	err = r.repository.concurrency.View(r.Context(), func(state *map[FunctionKey]int32, _ *memory.Transaction) error {
		for key, reserved := range *state {
			if key.Scope == scope {
				usage.ReservedConcurrency += int64(reserved)
			}
		}
		return nil
	})
	return usage, err
}

func (w memoryWriter) PutFunctionConcurrency(key FunctionKey, reserved int32) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, exists := (*w.state)[deploymentKey{FunctionKey: key}]; !exists {
		return ErrNotFound
	}
	return w.repository.concurrency.Update(w.Context(), func(state *map[FunctionKey]int32, _ *memory.Transaction) error {
		(*state)[key] = reserved
		return nil
	})
}

func (w memoryWriter) DeleteFunctionConcurrency(key FunctionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.concurrency.Update(w.Context(), func(state *map[FunctionKey]int32, _ *memory.Transaction) error {
		delete(*state, key)
		return nil
	})
}
