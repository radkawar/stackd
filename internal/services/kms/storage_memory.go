package kms

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"

	"stackd/storage/memory"
)

type memoryState struct {
	keySets map[KeyOwner]map[string]KeySetRecord
	keys    map[StorageScope]map[string]KeyRecord
	aliases map[StorageScope]map[string]AliasRecord
}

// MemoryStorage is a typed transactional KMS storage backend.
// All records are copied on ingress and egress, including key material.
type MemoryStorage struct {
	store *memory.Store[memoryState]
}

// NewMemoryStorage joins domain; nil constructs an independent domain.
func NewMemoryStorage(domain *memory.Domain) *MemoryStorage {
	initial := memoryState{keySets: make(map[KeyOwner]map[string]KeySetRecord), keys: make(map[StorageScope]map[string]KeyRecord), aliases: make(map[StorageScope]map[string]AliasRecord)}
	return &MemoryStorage{store: memory.New(domain, initial, func(state memoryState) memoryState {
		return memoryState{keySets: memory.CloneTables(state.keySets), keys: memory.CloneTables(state.keys), aliases: memory.CloneTables(state.aliases)}
	})}
}

func (s *MemoryStorage) View(ctx context.Context, fn func(Reader) error) error {
	return s.store.View(ctx, func(state *memoryState, tx *memory.Transaction) error {
		return fn(&memoryReader{state: state, tx: tx})
	})
}

func (s *MemoryStorage) Transact(ctx context.Context, fn func(Transaction) error) error {
	return s.store.Update(ctx, func(state *memoryState, tx *memory.Transaction) error {
		return fn(&memoryTransaction{memoryReader{state: state, tx: tx}})
	})
}

func (s *MemoryStorage) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return s.store.Attempt(ctx, func(state *memoryState, tx *memory.Transaction) error {
		return fn(&memoryTransaction{memoryReader{state: state, tx: tx}})
	})
}

type memoryReader struct {
	state *memoryState
	tx    *memory.Transaction
}

type memoryTransaction struct{ memoryReader }

func (tx *memoryReader) Context() context.Context { return tx.tx.Context() }

func (tx *memoryReader) Scopes() ([]StorageScope, error) {
	if err := tx.tx.Check(false); err != nil {
		return nil, err
	}
	var scopes []StorageScope
	for sc, keys := range tx.state.keys {
		if len(keys) != 0 {
			scopes = append(scopes, sc)
		}
	}
	slices.SortFunc(scopes, func(a, b StorageScope) int {
		return cmp.Or(strings.Compare(a.Partition, b.Partition), strings.Compare(a.AccountID, b.AccountID), strings.Compare(a.Region, b.Region))
	})
	return scopes, nil
}

func cloneKeySet(k KeySetRecord) KeySetRecord {
	k.Materials = slices.Clone(k.Materials)
	for i := range k.Materials {
		k.Materials[i].Material = slices.Clone(k.Materials[i].Material)
	}
	k.ReplicaRegions = slices.Clone(k.ReplicaRegions)
	return k
}

func cloneKeyRecord(k KeyRecord) KeyRecord {
	k.Imports = slices.Clone(k.Imports)
	for i := range k.Imports {
		if k.Imports[i].ValidTo != nil {
			k.Imports[i].ValidTo = ptr(*k.Imports[i].ValidTo)
		}
	}
	k.ImportParameters = slices.Clone(k.ImportParameters)
	for i := range k.ImportParameters {
		k.ImportParameters[i].Token = slices.Clone(k.ImportParameters[i].Token)
		k.ImportParameters[i].PrivateKey = slices.Clone(k.ImportParameters[i].PrivateKey)
	}
	k.Principals = slices.Clone(k.Principals)
	k.Tags = slices.Clone(k.Tags)
	k.Grants = slices.Clone(k.Grants)
	for i, g := range k.Grants {
		g.Operations, g.Tokens = slices.Clone(g.Operations), slices.Clone(g.Tokens)
		g.EncryptionContextEquals, g.EncryptionContextSubset = slices.Clone(g.EncryptionContextEquals), slices.Clone(g.EncryptionContextSubset)
		k.Grants[i] = g
	}
	if k.Deletion != nil {
		k.Deletion = ptr(*k.Deletion)
	}
	return k
}

func (tx *memoryReader) KeySet(owner KeyOwner, id string) (KeySetRecord, error) {
	if err := tx.tx.Check(false); err != nil {
		return KeySetRecord{}, err
	}
	set, ok := tx.state.keySets[owner][id]
	if !ok {
		return KeySetRecord{}, ErrKeySetNotFound
	}
	return cloneKeySet(set), nil
}

func (tx *memoryReader) MultiRegionPrimaryRegions(owner KeyOwner) ([]string, error) {
	if err := tx.tx.Check(false); err != nil {
		return nil, err
	}
	regions := make(map[string]struct{})
	for _, set := range tx.state.keySets[owner] {
		if set.MultiRegion {
			regions[set.PrimaryRegion] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(regions)), nil
}

func (tx *memoryTransaction) PutKeySet(owner KeyOwner, set KeySetRecord) error {
	if err := tx.tx.Check(true); err != nil {
		return err
	}
	if tx.state.keySets[owner] == nil {
		tx.state.keySets[owner] = make(map[string]KeySetRecord)
	}
	tx.state.keySets[owner][set.ID] = cloneKeySet(set)
	return nil
}

func (tx *memoryTransaction) DeleteKeySet(owner KeyOwner, id string) error {
	if err := tx.tx.Check(true); err != nil {
		return err
	}
	delete(tx.state.keySets[owner], id)
	return nil
}

func (tx *memoryReader) Keys(sc StorageScope) ([]KeyRecord, error) {
	if err := tx.tx.Check(false); err != nil {
		return nil, err
	}
	keys := tx.state.keys[sc]
	out := make([]KeyRecord, 0, len(keys))
	for _, id := range slices.Sorted(maps.Keys(keys)) {
		out = append(out, cloneKeyRecord(keys[id]))
	}
	return out, nil
}

func (tx *memoryReader) Aliases(sc StorageScope) ([]AliasRecord, error) {
	if err := tx.tx.Check(false); err != nil {
		return nil, err
	}
	aliases := tx.state.aliases[sc]
	out := make([]AliasRecord, 0, len(aliases))
	for _, name := range slices.Sorted(maps.Keys(aliases)) {
		out = append(out, aliases[name])
	}
	return out, nil
}

func (tx *memoryTransaction) PutKey(sc StorageScope, k KeyRecord) error {
	if err := tx.tx.Check(true); err != nil {
		return err
	}
	if tx.state.keys[sc] == nil {
		tx.state.keys[sc] = make(map[string]KeyRecord)
	}
	tx.state.keys[sc][k.ID] = cloneKeyRecord(k)
	return nil
}

func (tx *memoryTransaction) DeleteKey(sc StorageScope, id string) error {
	if err := tx.tx.Check(true); err != nil {
		return err
	}
	delete(tx.state.keys[sc], id)
	return nil
}

func (tx *memoryTransaction) PutAlias(sc StorageScope, a AliasRecord) error {
	if err := tx.tx.Check(true); err != nil {
		return err
	}
	if tx.state.aliases[sc] == nil {
		tx.state.aliases[sc] = make(map[string]AliasRecord)
	}
	tx.state.aliases[sc][a.Name] = a
	return nil
}

func (tx *memoryTransaction) DeleteAlias(sc StorageScope, name string) error {
	if err := tx.tx.Check(true); err != nil {
		return err
	}
	delete(tx.state.aliases[sc], name)
	return nil
}
