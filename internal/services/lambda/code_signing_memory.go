package lambda

import (
	"cmp"
	"errors"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type codeSigningState struct {
	Configs   map[CodeSigningConfigKey]CodeSigningConfigRecord
	Functions map[FunctionKey]CodeSigningConfigKey
}

func newCodeSigningStore(domain *memory.Domain) *memory.Store[codeSigningState] {
	return memory.New(domain, codeSigningState{Configs: map[CodeSigningConfigKey]CodeSigningConfigRecord{}, Functions: map[FunctionKey]CodeSigningConfigKey{}}, func(v codeSigningState) codeSigningState {
		return codeSigningState{Configs: maps.Clone(v.Configs), Functions: maps.Clone(v.Functions)}
	})
}

func cloneCodeSigningConfig(v CodeSigningConfigRecord) CodeSigningConfigRecord {
	v.Publishers = slices.Clone(v.Publishers)
	v.Tags = maps.Clone(v.Tags)
	return v
}

func (r memoryReader) CodeSigningConfig(k CodeSigningConfigKey) (v CodeSigningConfigRecord, err error) {
	err = r.repository.codeSigning.View(r.Context(), func(state *codeSigningState, _ *memory.Transaction) error {
		var ok bool
		v, ok = state.Configs[k]
		if !ok {
			return ErrNotFound
		}
		v = cloneCodeSigningConfig(v)
		return nil
	})
	return
}

func (r memoryReader) CodeSigningConfigs(scope Scope) (out []CodeSigningConfigRecord, err error) {
	err = r.repository.codeSigning.View(r.Context(), func(state *codeSigningState, _ *memory.Transaction) error {
		for key, v := range state.Configs {
			if key.Scope == scope {
				out = append(out, cloneCodeSigningConfig(v))
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b CodeSigningConfigRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return
}

func (r memoryReader) FunctionCodeSigningConfig(k FunctionKey) (out CodeSigningConfigKey, err error) {
	err = r.repository.codeSigning.View(r.Context(), func(state *codeSigningState, _ *memory.Transaction) error {
		var ok bool
		out, ok = state.Functions[k]
		if !ok {
			return ErrNotFound
		}
		return nil
	})
	return
}

func (r memoryReader) FunctionsByCodeSigningConfig(k CodeSigningConfigKey) (out []FunctionKey, err error) {
	err = r.repository.codeSigning.View(r.Context(), func(state *codeSigningState, _ *memory.Transaction) error {
		for function, config := range state.Functions {
			if config == k {
				out = append(out, function)
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b FunctionKey) int { return cmp.Compare(a.ARN(), b.ARN()) })
	return
}

func (w memoryWriter) PutCodeSigningConfig(v CodeSigningConfigRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.codeSigning.Update(w.Context(), func(state *codeSigningState, _ *memory.Transaction) error {
		state.Configs[v.Key] = cloneCodeSigningConfig(v)
		return nil
	})
}

func (w memoryWriter) DeleteCodeSigningConfig(k CodeSigningConfigKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.codeSigning.Update(w.Context(), func(state *codeSigningState, _ *memory.Transaction) error {
		for _, attached := range state.Functions {
			if attached == k {
				return errors.New("code signing configuration is in use")
			}
		}
		delete(state.Configs, k)
		return nil
	})
}

func (w memoryWriter) PutFunctionCodeSigningConfig(k FunctionKey, config CodeSigningConfigKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if k.Scope != config.Scope {
		return errors.New("code signing configuration must share the function scope")
	}
	return w.repository.codeSigning.Update(w.Context(), func(state *codeSigningState, _ *memory.Transaction) error {
		if _, ok := state.Configs[config]; !ok {
			return ErrNotFound
		}
		state.Functions[k] = config
		return nil
	})
}

func (w memoryWriter) DeleteFunctionCodeSigningConfig(k FunctionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.codeSigning.Update(w.Context(), func(state *codeSigningState, _ *memory.Transaction) error {
		delete(state.Functions, k)
		return nil
	})
}
