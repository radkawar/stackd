package lambda

import (
	"errors"
	"maps"

	"stackd/storage/memory"
)

type versionOwnerKey struct {
	FunctionKey
	VersionOwner
}

type versionOwnerState struct {
	Owners       map[FunctionVersionKey]VersionOwner
	Publications map[versionOwnerKey]uint64
}

func newVersionOwnerStore(domain *memory.Domain) *memory.Store[versionOwnerState] {
	return memory.New(domain, versionOwnerState{Owners: map[FunctionVersionKey]VersionOwner{}, Publications: map[versionOwnerKey]uint64{}}, func(v versionOwnerState) versionOwnerState {
		return versionOwnerState{Owners: maps.Clone(v.Owners), Publications: maps.Clone(v.Publications)}
	})
}

func (r memoryReader) OwnedFunctionVersion(k FunctionKey, owner VersionOwner) (FunctionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return FunctionRecord{}, err
	}
	var version uint64
	err := r.repository.versionOwners.View(r.Context(), func(rows *versionOwnerState, _ *memory.Transaction) error {
		var ok bool
		version, ok = rows.Publications[versionOwnerKey{k, owner}]
		if !ok {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return FunctionRecord{}, err
	}
	return r.FunctionVersion(FunctionVersionKey{FunctionKey: k, Version: version})
}

func (r memoryReader) FunctionVersionOwner(k FunctionVersionKey) (VersionOwner, error) {
	if err := r.tx.Check(false); err != nil {
		return VersionOwner{}, err
	}
	var owner VersionOwner
	err := r.repository.versionOwners.View(r.Context(), func(rows *versionOwnerState, _ *memory.Transaction) error {
		var ok bool
		owner, ok = rows.Owners[k]
		if !ok {
			return ErrNotFound
		}
		return nil
	})
	return owner, err
}

func (w memoryWriter) PutFunctionVersionOwner(k FunctionVersionKey, owner VersionOwner) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if k.Version == 0 || k.Version >= LatestPublishedVersion || owner.StackID == "" || owner.LogicalID == "" || owner.Token == "" {
		return errors.New("invalid Lambda version ownership receipt")
	}
	if _, exists := (*w.state)[deploymentKey{FunctionKey: k.FunctionKey, Version: k.Version}]; !exists {
		return ErrNotFound
	}
	return w.repository.versionOwners.Update(w.Context(), func(rows *versionOwnerState, _ *memory.Transaction) error {
		key := versionOwnerKey{k.FunctionKey, owner}
		if version, exists := rows.Publications[key]; exists && version != k.Version {
			return errors.New("lambda version owner already has a publication")
		}
		if existing, exists := rows.Owners[k]; exists && existing != owner {
			return errors.New("lambda publication already has an owner")
		}
		rows.Publications[key], rows.Owners[k] = k.Version, owner
		return nil
	})
}

func (w memoryWriter) deleteFunctionVersionOwners(k FunctionKey, version uint64) error {
	return w.repository.versionOwners.Update(w.Context(), func(rows *versionOwnerState, _ *memory.Transaction) error {
		for key, owner := range rows.Owners {
			if key.FunctionKey == k && (version == 0 || key.Version == version) {
				delete(rows.Owners, key)
				delete(rows.Publications, versionOwnerKey{k, owner})
			}
		}
		return nil
	})
}
