package lambda

import (
	"cmp"
	"errors"
	"math"
	"slices"
	"strconv"

	"stackd/storage/memory"
)

func (r memoryReader) FunctionVersion(k FunctionVersionKey) (FunctionRecord, error) {
	return r.function(deploymentKey{FunctionKey: k.FunctionKey, Version: k.Version})
}

func (r memoryReader) FunctionVersions(k FunctionKey) ([]FunctionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []FunctionRecord{}
	for key, value := range *r.state {
		if key.FunctionKey == k && key.Version != 0 {
			out = append(out, cloneFunction(value))
		}
	}
	slices.SortFunc(out, func(a, b FunctionRecord) int { return cmp.Compare(a.Version, b.Version) })
	return out, nil
}

func (r memoryReader) LastAllocatedVersion(k FunctionKey) (version uint64, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.allocations.View(r.Context(), func(rows *map[FunctionKey]uint64, _ *memory.Transaction) error {
		version = (*rows)[k]
		return nil
	})
	return
}

func (w memoryWriter) AllocateFunctionVersion(k FunctionKey) (version uint64, err error) {
	if err = w.tx.Check(true); err != nil {
		return
	}
	err = w.repository.allocations.Update(w.Context(), func(rows *map[FunctionKey]uint64, _ *memory.Transaction) error {
		if (*rows)[k] == math.MaxInt64 {
			return errors.New("function version allocation exhausted")
		}
		version = (*rows)[k] + 1
		(*rows)[k] = version
		return nil
	})
	return
}

func (w memoryWriter) PutFunctionVersion(v FunctionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if v.Version == 0 || v.Version > math.MaxInt64 {
		return errors.New("invalid published Lambda version")
	}
	key := deploymentKey{FunctionKey: v.Key, Version: v.Version}
	if _, exists := (*w.state)[key]; exists {
		return errors.New("published Lambda version already exists")
	}
	v.Tags = nil
	(*w.state)[key] = cloneFunction(v)
	return nil
}

func (w memoryWriter) SetPublishedDeploymentState(v FunctionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key, snapshot := range *w.state {
		if key.FunctionKey != v.Key || key.Version == 0 || snapshot.DeploymentRevision != v.DeploymentRevision {
			continue
		}
		snapshot.State, snapshot.StateReason, snapshot.StateReasonCode = v.State, v.StateReason, v.StateReasonCode
		snapshot.UpdateStatus, snapshot.UpdateReason = v.UpdateStatus, v.UpdateReason
		snapshot.Revision = v.Revision
		(*w.state)[key] = snapshot
	}
	return nil
}

func (w memoryWriter) DeleteFunctionVersion(k FunctionVersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if k.Version == 0 {
		return errors.New("cannot delete latest as a published version")
	}
	delete(*w.state, deploymentKey{FunctionKey: k.FunctionKey, Version: k.Version})
	if err := w.deleteFunctionVersionOwners(k.FunctionKey, k.Version); err != nil {
		return err
	}
	if err := w.DeleteRuntimeManagement(k); err != nil {
		return err
	}
	return w.deleteQualifiedControls(FunctionReference{FunctionKey: k.FunctionKey, Qualifier: strconv.FormatUint(k.Version, 10)})
}

func (r memoryReader) Alias(k FunctionReference) (v AliasRecord, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.aliases.View(r.Context(), func(rows *map[FunctionReference]AliasRecord, _ *memory.Transaction) error {
		var ok bool
		v, ok = (*rows)[k]
		if !ok {
			return ErrNotFound
		}
		return nil
	})
	return
}

func (r memoryReader) Aliases(k FunctionKey) (out []AliasRecord, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	out = []AliasRecord{}
	err = r.repository.aliases.View(r.Context(), func(rows *map[FunctionReference]AliasRecord, _ *memory.Transaction) error {
		for key, alias := range *rows {
			if key.FunctionKey == k {
				out = append(out, alias)
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b AliasRecord) int { return cmp.Compare(a.Key.Qualifier, b.Key.Qualifier) })
	return
}

func (w memoryWriter) PutAlias(v AliasRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, exists := (*w.state)[deploymentKey{FunctionKey: v.Key.FunctionKey}]; !exists {
		return ErrNotFound
	}
	return w.repository.aliases.Update(w.Context(), func(rows *map[FunctionReference]AliasRecord, _ *memory.Transaction) error {
		(*rows)[v.Key] = v
		return nil
	})
}

func (w memoryWriter) DeleteAlias(k FunctionReference) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if err := w.repository.aliases.Update(w.Context(), func(rows *map[FunctionReference]AliasRecord, _ *memory.Transaction) error {
		delete(*rows, k)
		return nil
	}); err != nil {
		return err
	}
	return w.deleteQualifiedControls(k)
}

func (w memoryWriter) deleteQualifiedControls(k FunctionReference) error {
	if err := w.DeleteProvisionedConcurrency(k); err != nil {
		return err
	}
	if err := w.DeleteFunctionPolicy(k); err != nil {
		return err
	}
	return w.DeleteEventInvokeConfig(k)
}

func (w memoryWriter) deleteFunctionControls(k FunctionKey) error {
	if err := w.repository.aliases.Update(w.Context(), func(rows *map[FunctionReference]AliasRecord, _ *memory.Transaction) error {
		for key := range *rows {
			if key.FunctionKey == k {
				delete(*rows, key)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := w.repository.policies.Update(w.Context(), func(rows *map[FunctionReference]FunctionPolicy, _ *memory.Transaction) error {
		for key := range *rows {
			if key.FunctionKey == k {
				delete(*rows, key)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return w.repository.configs.Update(w.Context(), func(rows *map[FunctionReference]EventInvokeConfig, _ *memory.Transaction) error {
		for key := range *rows {
			if key.FunctionKey == k {
				delete(*rows, key)
			}
		}
		return nil
	})
}

func (r memoryReader) EventInvokeConfigs(k FunctionKey) (out []EventInvokeConfig, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	out = []EventInvokeConfig{}
	err = r.repository.configs.View(r.Context(), func(rows *map[FunctionReference]EventInvokeConfig, _ *memory.Transaction) error {
		for key, config := range *rows {
			if key.FunctionKey == k {
				out = append(out, cloneEventInvokeConfig(config))
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b EventInvokeConfig) int { return cmp.Compare(a.Key.Qualifier, b.Key.Qualifier) })
	return
}
