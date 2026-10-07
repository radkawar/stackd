package cognitoidp

import (
	"cmp"
	"slices"
)

func (r memoryReader) Ownership(k OwnershipKey) (OwnershipRecord, error) {
	return memoryRow(r.tx, r.s.ownership, k, func(v OwnershipRecord) OwnershipRecord { return v })
}

func (r memoryReader) PoolOwnership(scope Scope, owner ResourceOwner) (OwnershipRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return OwnershipRecord{}, err
	}
	for key, v := range r.s.ownership {
		if key.Scope == scope && key.Kind == OwnerKindPool && v.Owner == owner {
			return v, nil
		}
	}
	return OwnershipRecord{}, ErrNotFound
}

func (w memoryWriter) PutOwnership(v OwnershipRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.ownership[v.Key] = v
	return nil
}

func (w memoryWriter) DeleteOwnership(k OwnershipKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.ownership, k)
	return nil
}

// releaseOwners removes the claims of a deleted pool child. Callers have
// already checked the write transaction.
func (w memoryWriter) releaseOwners(pool PoolKey, match func(OwnershipRecord) bool) {
	for key, v := range w.s.ownership {
		if key.PoolKey == pool && match(v) {
			delete(w.s.ownership, key)
		}
	}
}

func (r memoryReader) Provider(k ProviderKey) (ProviderRecord, error) {
	return memoryRow(r.tx, r.s.providers, k, copyProvider)
}

func (r memoryReader) Providers(k PoolKey) ([]ProviderRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := []ProviderRecord{}
	for key, row := range r.s.providers {
		if key.PoolKey == k {
			rows = append(rows, copyProvider(row))
		}
	}
	slices.SortFunc(rows, func(a, b ProviderRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return rows, nil
}

func (w memoryWriter) PutProvider(v ProviderRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.providers[v.Key] = copyProvider(v)
	return nil
}

func (w memoryWriter) DeleteProvider(k ProviderKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.providers, k)
	w.releaseOwners(k.PoolKey, func(v OwnershipRecord) bool { return v.Key.Kind == OwnerKindProvider && v.PhysicalID == k.Name })
	return nil
}

func (r memoryReader) ClientsByID(partition, id string) ([]ClientRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := []ClientRecord{}
	for index, key := range r.s.clientIDs {
		if index.partition == partition && index.id == id {
			rows = append(rows, copyClientRecord(r.s.clients[key]))
		}
	}
	slices.SortFunc(rows, func(a, b ClientRecord) int { return cmp.Compare(a.Key.Region, b.Key.Region) })
	return rows, nil
}

func (r memoryReader) PoolByDomain(partition, region, domain string) (PoolRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return PoolRecord{}, err
	}
	for key, pool := range r.s.pools {
		if key.Partition == partition && key.Region == region && value(pool.Data.Domain) == domain {
			return copyPoolRecord(pool), nil
		}
	}
	return PoolRecord{}, ErrNotFound
}
