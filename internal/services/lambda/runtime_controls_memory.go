package lambda

import (
	"cmp"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type runtimeControlState struct {
	Recursion   map[FunctionKey]string
	Management  map[FunctionVersionKey]string
	Provisioned map[FunctionReference]ProvisionedConcurrencyRecord
}

func newRuntimeControlStore(domain *memory.Domain) *memory.Store[runtimeControlState] {
	return memory.New(domain, runtimeControlState{Recursion: map[FunctionKey]string{}, Management: map[FunctionVersionKey]string{}, Provisioned: map[FunctionReference]ProvisionedConcurrencyRecord{}}, func(v runtimeControlState) runtimeControlState {
		return runtimeControlState{Recursion: maps.Clone(v.Recursion), Management: maps.Clone(v.Management), Provisioned: maps.Clone(v.Provisioned)}
	})
}

func (r memoryReader) RecursiveLoop(key FunctionKey) (string, error) {
	value := "Terminate"
	if err := r.tx.Check(false); err != nil {
		return "", err
	}
	err := r.repository.runtimeControls.View(r.Context(), func(state *runtimeControlState, _ *memory.Transaction) error {
		if v, ok := state.Recursion[key]; ok {
			value = v
		}
		return nil
	})
	return value, err
}
func (r memoryReader) RuntimeManagement(key FunctionVersionKey) (string, error) {
	value := "Auto"
	if err := r.tx.Check(false); err != nil {
		return "", err
	}
	err := r.repository.runtimeControls.View(r.Context(), func(state *runtimeControlState, _ *memory.Transaction) error {
		if v, ok := state.Management[key]; ok {
			value = v
		}
		return nil
	})
	return value, err
}
func (r memoryReader) ProvisionedConcurrency(key FunctionReference) (ProvisionedConcurrencyRecord, error) {
	var value ProvisionedConcurrencyRecord
	if err := r.tx.Check(false); err != nil {
		return value, err
	}
	err := r.repository.runtimeControls.View(r.Context(), func(state *runtimeControlState, _ *memory.Transaction) error {
		var ok bool
		value, ok = state.Provisioned[key]
		if !ok {
			return ErrNotFound
		}
		return nil
	})
	return value, err
}
func (r memoryReader) AllProvisionedConcurrency() ([]ProvisionedConcurrencyRecord, error) {
	var rows []ProvisionedConcurrencyRecord
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	err := r.repository.runtimeControls.View(r.Context(), func(state *runtimeControlState, _ *memory.Transaction) error {
		for _, row := range state.Provisioned {
			rows = append(rows, row)
		}
		return nil
	})
	slices.SortFunc(rows, func(a, b ProvisionedConcurrencyRecord) int { return cmp.Compare(a.Key.ARN(), b.Key.ARN()) })
	return rows, err
}
func (w memoryWriter) PutRecursiveLoop(key FunctionKey, mode string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.runtimeControls.Update(w.Context(), func(state *runtimeControlState, _ *memory.Transaction) error { state.Recursion[key] = mode; return nil })
}
func (w memoryWriter) PutRuntimeManagement(key FunctionVersionKey, mode string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.runtimeControls.Update(w.Context(), func(state *runtimeControlState, _ *memory.Transaction) error {
		state.Management[key] = mode
		return nil
	})
}
func (w memoryWriter) DeleteRuntimeManagement(key FunctionVersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.runtimeControls.Update(w.Context(), func(state *runtimeControlState, _ *memory.Transaction) error {
		delete(state.Management, key)
		return nil
	})
}
func (w memoryWriter) PutProvisionedConcurrency(row ProvisionedConcurrencyRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.runtimeControls.Update(w.Context(), func(state *runtimeControlState, _ *memory.Transaction) error {
		state.Provisioned[row.Key] = row
		return nil
	})
}
func (w memoryWriter) DeleteProvisionedConcurrency(key FunctionReference) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.runtimeControls.Update(w.Context(), func(state *runtimeControlState, _ *memory.Transaction) error {
		delete(state.Provisioned, key)
		return nil
	})
}
func (w memoryWriter) deleteRuntimeControls(key FunctionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.runtimeControls.Update(w.Context(), func(state *runtimeControlState, _ *memory.Transaction) error {
		delete(state.Recursion, key)
		for ref := range state.Management {
			if ref.FunctionKey == key {
				delete(state.Management, ref)
			}
		}
		for ref := range state.Provisioned {
			if ref.FunctionKey == key {
				delete(state.Provisioned, ref)
			}
		}
		return nil
	})
}
