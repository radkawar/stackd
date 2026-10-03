package identity

import (
	"context"
	"maps"

	"stackd/storage/memory"
)

// MemoryRepository is a transactional process-local implementation. Credential
// issuance, status checks, quotas and session rules remain in Store.
type MemoryRepository struct {
	store *memory.Store[map[string]Record]
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{store: memory.New(nil, make(map[string]Record), maps.Clone[map[string]Record])}
}

func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(records *map[string]Record, tx *memory.Transaction) error {
		return fn(memoryReader{records: records, tx: tx})
	})
}

func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(records *map[string]Record, tx *memory.Transaction) error {
		return fn(memoryTransaction{memoryReader{records: records, tx: tx}})
	})
}

type memoryReader struct {
	records *map[string]Record
	tx      *memory.Transaction
}

func (r memoryReader) Get(key string) (Record, error) {
	if err := r.tx.Check(false); err != nil {
		return Record{}, err
	}
	v, ok := (*r.records)[key]
	if !ok {
		return Record{}, ErrNotFound
	}
	v.Credential = cloneCredential(v.Credential)
	return v, nil
}

func (r memoryReader) FindPrincipal(accountID, principalID string) ([]Record, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var records []Record
	for _, v := range *r.records {
		c := v.Credential
		if c.AccountID == accountID && (c.PrincipalID == principalID || c.IssuerID == principalID) {
			v.Credential = cloneCredential(c)
			records = append(records, v)
		}
	}
	return records, nil
}

type memoryTransaction struct{ memoryReader }

func (t memoryTransaction) Put(v Record) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	v.Credential = cloneCredential(v.Credential)
	(*t.records)[v.Credential.AccessKeyID] = v
	return nil
}

func (t memoryTransaction) Delete(key string) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	if _, ok := (*t.records)[key]; !ok {
		return ErrNotFound
	}
	delete(*t.records, key)
	return nil
}
