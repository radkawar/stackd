package lambda

import (
	"maps"

	"stackd/storage/memory"
)

func (r memoryReader) FunctionPolicy(key FunctionReference) (FunctionPolicy, error) {
	if err := r.tx.Check(false); err != nil {
		return FunctionPolicy{}, err
	}
	var result FunctionPolicy
	err := r.repository.policies.View(r.Context(), func(state *map[FunctionReference]FunctionPolicy, _ *memory.Transaction) error {
		var ok bool
		result, ok = (*state)[key]
		if !ok {
			return ErrNotFound
		}
		result.PrincipalIDs = maps.Clone(result.PrincipalIDs)
		return nil
	})
	return result, err
}

func (w memoryWriter) PutFunctionPolicy(value FunctionPolicy) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, exists := (*w.state)[deploymentKey{FunctionKey: value.Key.FunctionKey}]; !exists {
		return ErrNotFound
	}
	return w.repository.policies.Update(w.Context(), func(state *map[FunctionReference]FunctionPolicy, _ *memory.Transaction) error {
		value.PrincipalIDs = maps.Clone(value.PrincipalIDs)
		(*state)[value.Key] = value
		return nil
	})
}

func (w memoryWriter) DeleteFunctionPolicy(key FunctionReference) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.policies.Update(w.Context(), func(state *map[FunctionReference]FunctionPolicy, _ *memory.Transaction) error {
		delete(*state, key)
		return nil
	})
}
