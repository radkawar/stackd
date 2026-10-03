package lambda

import (
	"cmp"
	"errors"
	"maps"
	"math"
	"slices"
	"stackd/storage/memory"
)

func cloneS3Reference(v *S3ObjectReference) *S3ObjectReference {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}
func cloneLayer(v LayerVersionRecord) LayerVersionRecord {
	v.CompatibleRuntimes = slices.Clone(v.CompatibleRuntimes)
	v.CompatibleArchitectures = slices.Clone(v.CompatibleArchitectures)
	v.Reference = cloneS3Reference(v.Reference)
	return v
}
func (r memoryReader) LayerVersion(k LayerVersionKey) (LayerVersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return LayerVersionRecord{}, err
	}
	var out LayerVersionRecord
	err := r.repository.layers.View(r.Context(), func(state *map[LayerVersionKey]LayerVersionRecord, _ *memory.Transaction) error {
		v, ok := (*state)[k]
		if !ok {
			return ErrNotFound
		}
		out = cloneLayer(v)
		return nil
	})
	return out, err
}
func (r memoryReader) OwnedLayerVersion(k LayerKey, owner LayerVersionOwner) (LayerVersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return LayerVersionRecord{}, err
	}
	if owner.StackID == "" || owner.LogicalID == "" || owner.Token == "" {
		return LayerVersionRecord{}, ErrNotFound
	}
	var out LayerVersionRecord
	err := r.repository.layers.View(r.Context(), func(state *map[LayerVersionKey]LayerVersionRecord, _ *memory.Transaction) error {
		for key, v := range *state {
			if key.LayerKey == k && v.Owner == owner {
				out = cloneLayer(v)
				return nil
			}
		}
		return ErrNotFound
	})
	return out, err
}
func (r memoryReader) LayerVersions(k LayerKey) ([]LayerVersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []LayerVersionRecord{}
	err := r.repository.layers.View(r.Context(), func(state *map[LayerVersionKey]LayerVersionRecord, _ *memory.Transaction) error {
		for key, v := range *state {
			if key.LayerKey == k {
				out = append(out, cloneLayer(v))
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b LayerVersionRecord) int { return cmp.Compare(b.Key.Version, a.Key.Version) })
	return out, err
}
func (r memoryReader) Layers(scope Scope) ([]LayerVersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	latest := map[LayerKey]LayerVersionRecord{}
	err := r.repository.layers.View(r.Context(), func(state *map[LayerVersionKey]LayerVersionRecord, _ *memory.Transaction) error {
		for key, v := range *state {
			if key.Scope == scope && key.Version > latest[key.LayerKey].Key.Version {
				latest[key.LayerKey] = v
			}
		}
		return nil
	})
	out := make([]LayerVersionRecord, 0, len(latest))
	for _, v := range latest {
		out = append(out, cloneLayer(v))
	}
	slices.SortFunc(out, func(a, b LayerVersionRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, err
}
func (w memoryWriter) AllocateLayerVersion(k LayerKey) (uint64, error) {
	if err := w.tx.Check(true); err != nil {
		return 0, err
	}
	var next uint64
	err := w.repository.layerAllocations.Update(w.Context(), func(state *map[LayerKey]uint64, _ *memory.Transaction) error {
		if (*state)[k] == math.MaxInt64 {
			return errors.New("layer version allocation exhausted")
		}
		next = (*state)[k] + 1
		(*state)[k] = next
		return nil
	})
	return next, err
}
func (w memoryWriter) PutLayerVersion(v LayerVersionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if v.Key.Version == 0 || v.Key.Version > math.MaxInt64 {
		return errors.New("invalid Lambda layer version")
	}
	if v.Owner != (LayerVersionOwner{}) && (v.Owner.StackID == "" || v.Owner.LogicalID == "" || v.Owner.Token == "") {
		return errors.New("incomplete Lambda layer version owner")
	}
	return w.repository.layers.Update(w.Context(), func(state *map[LayerVersionKey]LayerVersionRecord, _ *memory.Transaction) error {
		if _, ok := (*state)[v.Key]; ok {
			return errors.New("published Lambda layer version already exists")
		}
		if v.Owner != (LayerVersionOwner{}) {
			for key, existing := range *state {
				if key.LayerKey == v.Key.LayerKey && existing.Owner == v.Owner {
					return errors.New("lambda layer version owner already has a publication")
				}
			}
		}
		(*state)[v.Key] = cloneLayer(v)
		return nil
	})
}
func (w memoryWriter) DeleteLayerVersion(k LayerVersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if err := w.repository.layers.Update(w.Context(), func(state *map[LayerVersionKey]LayerVersionRecord, _ *memory.Transaction) error {
		delete(*state, k)
		return nil
	}); err != nil {
		return err
	}
	return w.DeleteLayerPolicy(k)
}
func (r memoryReader) LayerPolicy(k LayerVersionKey) (LayerPolicy, error) {
	if err := r.tx.Check(false); err != nil {
		return LayerPolicy{}, err
	}
	var out LayerPolicy
	err := r.repository.layerPolicies.View(r.Context(), func(state *map[LayerVersionKey]LayerPolicy, _ *memory.Transaction) error {
		v, ok := (*state)[k]
		if !ok {
			return ErrNotFound
		}
		v.PrincipalIDs = maps.Clone(v.PrincipalIDs)
		out = v
		return nil
	})
	return out, err
}
func (w memoryWriter) PutLayerPolicy(v LayerPolicy) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, err := w.LayerVersion(v.Key); err != nil {
		return err
	}
	return w.repository.layerPolicies.Update(w.Context(), func(state *map[LayerVersionKey]LayerPolicy, _ *memory.Transaction) error {
		v.PrincipalIDs = maps.Clone(v.PrincipalIDs)
		(*state)[v.Key] = v
		return nil
	})
}
func (w memoryWriter) DeleteLayerPolicy(k LayerVersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if err := w.repository.layerPermissionOwners.Update(w.Context(), func(state *map[LayerPermissionKey]LayerPermissionOwner, _ *memory.Transaction) error {
		for key := range *state {
			if key.LayerVersionKey == k {
				delete(*state, key)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return w.repository.layerPolicies.Update(w.Context(), func(state *map[LayerVersionKey]LayerPolicy, _ *memory.Transaction) error {
		delete(*state, k)
		return nil
	})
}

func (r memoryReader) LayerPermissionOwner(k LayerPermissionKey) (LayerPermissionOwner, error) {
	if err := r.tx.Check(false); err != nil {
		return LayerPermissionOwner{}, err
	}
	var out LayerPermissionOwner
	err := r.repository.layerPermissionOwners.View(r.Context(), func(state *map[LayerPermissionKey]LayerPermissionOwner, _ *memory.Transaction) error {
		var ok bool
		out, ok = (*state)[k]
		if !ok {
			return ErrNotFound
		}
		return nil
	})
	return out, err
}

func (w memoryWriter) PutLayerPermissionOwner(k LayerPermissionKey, owner LayerPermissionOwner) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if k.StatementID == "" || owner.StackID == "" || owner.LogicalID == "" || owner.Token == "" {
		return errors.New("incomplete Lambda layer permission owner")
	}
	if _, err := w.LayerPolicy(k.LayerVersionKey); err != nil {
		return err
	}
	return w.repository.layerPermissionOwners.Update(w.Context(), func(state *map[LayerPermissionKey]LayerPermissionOwner, _ *memory.Transaction) error {
		if _, ok := (*state)[k]; ok {
			return errors.New("lambda layer permission owner already exists")
		}
		(*state)[k] = owner
		return nil
	})
}

func (w memoryWriter) DeleteLayerPermissionOwner(k LayerPermissionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.layerPermissionOwners.Update(w.Context(), func(state *map[LayerPermissionKey]LayerPermissionOwner, _ *memory.Transaction) error {
		delete(*state, k)
		return nil
	})
}

// layerCodeReferences includes catalog versions and deleted versions retained by
// deployments. Identity is version scoped so catalog/attachment overlap counts once.
func (r memoryReader) layerCodeReferences() (map[LayerVersionKey]LayerAttachment, error) {
	out := map[LayerVersionKey]LayerAttachment{}
	for _, f := range *r.state {
		for _, v := range f.Layers {
			out[v.Key] = v
		}
	}
	err := r.repository.layers.View(r.Context(), func(state *map[LayerVersionKey]LayerVersionRecord, _ *memory.Transaction) error {
		for key, v := range *state {
			out[key] = LayerAttachment{Key: key, CodeSHA256: v.CodeSHA256, CodeSize: v.CodeSize}
		}
		return nil
	})
	return out, err
}
