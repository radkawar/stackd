package lambda

import (
	"cmp"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type capacityState struct {
	Providers    map[CapacityProviderKey]CapacityProviderRecord
	Scalings     map[FunctionReference]CapacityScalingRecord
	Guests       map[string]CapacityGuestRecord
	Environments map[string]CapacityEnvironmentRecord
}

func newCapacityStore(domain *memory.Domain) *memory.Store[capacityState] {
	return memory.New(domain, capacityState{Providers: map[CapacityProviderKey]CapacityProviderRecord{}, Scalings: map[FunctionReference]CapacityScalingRecord{}, Guests: map[string]CapacityGuestRecord{}, Environments: map[string]CapacityEnvironmentRecord{}}, func(s capacityState) capacityState {
		return capacityState{Providers: maps.Clone(s.Providers), Scalings: maps.Clone(s.Scalings), Guests: maps.Clone(s.Guests), Environments: maps.Clone(s.Environments)}
	})
}
func cloneCapacityProvider(v CapacityProviderRecord) CapacityProviderRecord {
	v.SubnetIDs = slices.Clone(v.SubnetIDs)
	v.SecurityGroupIDs = slices.Clone(v.SecurityGroupIDs)
	v.AllowedInstanceTypes = slices.Clone(v.AllowedInstanceTypes)
	v.ExcludedInstanceTypes = slices.Clone(v.ExcludedInstanceTypes)
	v.Tags = maps.Clone(v.Tags)
	v.PropagateTags = maps.Clone(v.PropagateTags)
	return v
}
func cloneCapacityGuest(v CapacityGuestRecord) CapacityGuestRecord {
	v.AgentCertificate = slices.Clone(v.AgentCertificate)
	v.AgentPrivateKey = slices.Clone(v.AgentPrivateKey)
	return v
}
func cloneCapacityFunction(v *CapacityFunctionConfig) *CapacityFunctionConfig {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}
func (r memoryReader) capacityView(fn func(*capacityState) error) error {
	if err := r.tx.Check(false); err != nil {
		return err
	}
	return r.repository.capacity.View(r.Context(), func(s *capacityState, _ *memory.Transaction) error { return fn(s) })
}
func (w memoryWriter) capacityUpdate(fn func(*capacityState) error) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.capacity.Update(w.Context(), func(s *capacityState, _ *memory.Transaction) error { return fn(s) })
}
func (r memoryReader) CapacityProvider(k CapacityProviderKey) (CapacityProviderRecord, error) {
	var out CapacityProviderRecord
	err := r.capacityView(func(s *capacityState) error {
		v, ok := s.Providers[k]
		if !ok {
			return ErrNotFound
		}
		out = cloneCapacityProvider(v)
		return nil
	})
	return out, err
}
func (r memoryReader) CapacityProviders(scope Scope) ([]CapacityProviderRecord, error) {
	return r.capacityProviders(&scope)
}
func (r memoryReader) AllCapacityProviders() ([]CapacityProviderRecord, error) {
	return r.capacityProviders(nil)
}
func (r memoryReader) capacityProviders(scope *Scope) ([]CapacityProviderRecord, error) {
	out := []CapacityProviderRecord{}
	err := r.capacityView(func(s *capacityState) error {
		for _, v := range s.Providers {
			if scope == nil || v.Key.Scope == *scope {
				out = append(out, cloneCapacityProvider(v))
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b CapacityProviderRecord) int { return cmp.Compare(a.Key.ARN(), b.Key.ARN()) })
	return out, err
}
func (r memoryReader) CapacityScaling(k FunctionReference) (CapacityScalingRecord, error) {
	var out CapacityScalingRecord
	err := r.capacityView(func(s *capacityState) error {
		var ok bool
		out, ok = s.Scalings[k]
		if !ok {
			return ErrNotFound
		}
		return nil
	})
	return out, err
}
func (r memoryReader) CapacityScalings(k FunctionKey) ([]CapacityScalingRecord, error) {
	out := []CapacityScalingRecord{}
	err := r.capacityView(func(s *capacityState) error {
		for key, v := range s.Scalings {
			if key.FunctionKey == k {
				out = append(out, v)
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b CapacityScalingRecord) int { return cmp.Compare(a.Key.ARN(), b.Key.ARN()) })
	return out, err
}
func (r memoryReader) CapacityGuests(k CapacityProviderKey) ([]CapacityGuestRecord, error) {
	out := []CapacityGuestRecord{}
	err := r.capacityView(func(s *capacityState) error {
		for _, v := range s.Guests {
			if v.Provider == k {
				out = append(out, cloneCapacityGuest(v))
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b CapacityGuestRecord) int { return cmp.Compare(a.ID, b.ID) })
	return out, err
}
func (r memoryReader) CapacityEnvironments(k FunctionVersionKey) ([]CapacityEnvironmentRecord, error) {
	return r.capacityEnvironments(&k)
}
func (r memoryReader) AllCapacityEnvironments() ([]CapacityEnvironmentRecord, error) {
	return r.capacityEnvironments(nil)
}
func (r memoryReader) capacityEnvironments(k *FunctionVersionKey) ([]CapacityEnvironmentRecord, error) {
	out := []CapacityEnvironmentRecord{}
	err := r.capacityView(func(s *capacityState) error {
		for _, v := range s.Environments {
			if k == nil || v.Key == *k {
				out = append(out, v)
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b CapacityEnvironmentRecord) int { return cmp.Compare(a.ID, b.ID) })
	return out, err
}
func (w memoryWriter) PutCapacityProvider(v CapacityProviderRecord) error {
	return w.capacityUpdate(func(s *capacityState) error { s.Providers[v.Key] = cloneCapacityProvider(v); return nil })
}
func (w memoryWriter) DeleteCapacityProvider(k CapacityProviderKey) error {
	return w.capacityUpdate(func(s *capacityState) error { delete(s.Providers, k); return nil })
}
func (w memoryWriter) PutCapacityScaling(v CapacityScalingRecord) error {
	return w.capacityUpdate(func(s *capacityState) error { s.Scalings[v.Key] = v; return nil })
}
func (w memoryWriter) DeleteCapacityScaling(k FunctionReference) error {
	return w.capacityUpdate(func(s *capacityState) error { delete(s.Scalings, k); return nil })
}
func (w memoryWriter) PutCapacityGuest(v CapacityGuestRecord) error {
	return w.capacityUpdate(func(s *capacityState) error { s.Guests[v.ID] = cloneCapacityGuest(v); return nil })
}
func (w memoryWriter) DeleteCapacityGuest(k CapacityProviderKey, id string) error {
	return w.capacityUpdate(func(s *capacityState) error {
		if v, ok := s.Guests[id]; ok && v.Provider == k {
			delete(s.Guests, id)
		}
		return nil
	})
}
func (w memoryWriter) PutCapacityEnvironment(v CapacityEnvironmentRecord) error {
	return w.capacityUpdate(func(s *capacityState) error { s.Environments[v.ID] = v; return nil })
}
func (w memoryWriter) DeleteCapacityEnvironment(id string) error {
	return w.capacityUpdate(func(s *capacityState) error { delete(s.Environments, id); return nil })
}
func (w memoryWriter) ReplaceCapacityPublishedFunction(v FunctionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if v.Version != LatestPublishedVersion || v.Capacity == nil {
		return capacityParameter("Invalid managed published version.")
	}
	v.Tags = nil
	(*w.state)[deploymentKey{FunctionKey: v.Key, Version: v.Version}] = cloneFunction(v)
	return nil
}
func (w memoryWriter) SetCapacityDeploymentState(v FunctionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	key := deploymentKey{FunctionKey: v.Key, Version: v.Version}
	current, ok := (*w.state)[key]
	if !ok {
		return ErrNotFound
	}
	if current.DeploymentRevision != v.DeploymentRevision {
		return nil
	}
	current.State, current.StateReason, current.StateReasonCode, current.Revision = v.State, v.StateReason, v.StateReasonCode, v.Revision
	(*w.state)[key] = current
	return nil
}
