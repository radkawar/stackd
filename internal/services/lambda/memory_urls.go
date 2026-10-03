package lambda

import (
	"cmp"
	"errors"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type functionURLState struct {
	Records map[FunctionReference]FunctionURLRecord
	IDs     map[string]FunctionReference
}

func cloneFunctionURLState(v functionURLState) functionURLState {
	return functionURLState{Records: maps.Clone(v.Records), IDs: maps.Clone(v.IDs)}
}

func (r memoryReader) FunctionURL(k FunctionReference) (FunctionURLRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return FunctionURLRecord{}, err
	}
	var out FunctionURLRecord
	err := r.repository.urls.View(r.Context(), func(state *functionURLState, _ *memory.Transaction) error {
		v, ok := state.Records[k]
		if !ok {
			return ErrNotFound
		}
		out = cloneFunctionURL(v)
		return nil
	})
	return out, err
}

func (r memoryReader) FunctionURLByID(id string) (FunctionURLRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return FunctionURLRecord{}, err
	}
	var out FunctionURLRecord
	err := r.repository.urls.View(r.Context(), func(state *functionURLState, _ *memory.Transaction) error {
		key, ok := state.IDs[id]
		if !ok {
			return ErrNotFound
		}
		out = cloneFunctionURL(state.Records[key])
		return nil
	})
	return out, err
}

func (r memoryReader) FunctionURLs(k FunctionKey) ([]FunctionURLRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []FunctionURLRecord{}
	err := r.repository.urls.View(r.Context(), func(state *functionURLState, _ *memory.Transaction) error {
		for key, v := range state.Records {
			if key.FunctionKey == k {
				out = append(out, cloneFunctionURL(v))
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b FunctionURLRecord) int { return cmp.Compare(a.Key.Qualifier, b.Key.Qualifier) })
	return out, err
}

func (w memoryWriter) PutFunctionURL(v FunctionURLRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, exists := (*w.state)[deploymentKey{FunctionKey: v.Key.FunctionKey}]; !exists {
		return ErrNotFound
	}
	return w.repository.urls.Update(w.Context(), func(state *functionURLState, _ *memory.Transaction) error {
		if key, ok := state.IDs[v.ID]; ok && key != v.Key {
			return errors.New("lambda function URL ID already exists")
		}
		if previous, ok := state.Records[v.Key]; ok {
			delete(state.IDs, previous.ID)
		}
		state.Records[v.Key] = cloneFunctionURL(v)
		state.IDs[v.ID] = v.Key
		return nil
	})
}

func (w memoryWriter) DeleteFunctionURL(k FunctionReference) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.urls.Update(w.Context(), func(state *functionURLState, _ *memory.Transaction) error {
		if v, ok := state.Records[k]; ok {
			delete(state.IDs, v.ID)
			delete(state.Records, k)
		}
		return nil
	})
}

func (w memoryWriter) deleteFunctionURLs(k FunctionKey) error {
	return w.repository.urls.Update(w.Context(), func(state *functionURLState, _ *memory.Transaction) error {
		for key, v := range state.Records {
			if key.FunctionKey == k {
				delete(state.IDs, v.ID)
				delete(state.Records, key)
			}
		}
		return nil
	})
}
