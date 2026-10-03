package account

import (
	"context"
	"maps"

	"stackd/storage/memory"
)

type memoryState struct {
	regions      map[RegionKey]RegionRecord
	contacts     map[Scope]ContactInformation
	alternate    map[AlternateContactKey]AlternateContact
	emailUpdates map[Scope]PrimaryEmailUpdate
}

type memoryRepository struct{ store *memory.Store[memoryState] }
type memoryTx struct {
	tx    *memory.Transaction
	state *memoryState
}

// NewMemoryRepository joins the supplied transaction domain.
func NewMemoryRepository(domain *memory.Domain) Repository {
	initial := memoryState{regions: make(map[RegionKey]RegionRecord), contacts: make(map[Scope]ContactInformation), alternate: make(map[AlternateContactKey]AlternateContact), emailUpdates: make(map[Scope]PrimaryEmailUpdate)}
	return &memoryRepository{memory.New(domain, initial, func(s memoryState) memoryState {
		return memoryState{regions: maps.Clone(s.regions), contacts: maps.Clone(s.contacts), alternate: maps.Clone(s.alternate), emailUpdates: maps.Clone(s.emailUpdates)}
	})}
}

func (r *memoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return r.store.View(ctx, func(state *memoryState, tx *memory.Transaction) error { return fn(&memoryTx{tx, state}) })
}
func (r *memoryRepository) Update(ctx context.Context, fn func(Writer) error) error {
	return r.store.Update(ctx, func(state *memoryState, tx *memory.Transaction) error { return fn(&memoryTx{tx, state}) })
}
func (t *memoryTx) Context() context.Context { return t.tx.Context() }
func (t *memoryTx) Region(key RegionKey) (RegionRecord, bool, error) {
	if err := t.tx.Check(false); err != nil {
		return RegionRecord{}, false, err
	}
	record, found := t.state.regions[key]
	return record, found, nil
}
func (t *memoryTx) PutRegion(key RegionKey, record RegionRecord) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	t.state.regions[key] = record
	return nil
}
func (t *memoryTx) Contact(scope Scope) (ContactInformation, bool, error) {
	if err := t.tx.Check(false); err != nil {
		return ContactInformation{}, false, err
	}
	record, found := t.state.contacts[scope]
	return record, found, nil
}
func (t *memoryTx) PutContact(scope Scope, record ContactInformation) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	t.state.contacts[scope] = record
	return nil
}
func (t *memoryTx) AlternateContact(key AlternateContactKey) (AlternateContact, bool, error) {
	if err := t.tx.Check(false); err != nil {
		return AlternateContact{}, false, err
	}
	record, found := t.state.alternate[key]
	return record, found, nil
}
func (t *memoryTx) PutAlternateContact(key AlternateContactKey, record AlternateContact) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	t.state.alternate[key] = record
	return nil
}
func (t *memoryTx) DeleteAlternateContact(key AlternateContactKey) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	delete(t.state.alternate, key)
	return nil
}

func (t *memoryTx) PrimaryEmailUpdate(scope Scope) (PrimaryEmailUpdate, bool, error) {
	if err := t.tx.Check(false); err != nil {
		return PrimaryEmailUpdate{}, false, err
	}
	record, found := t.state.emailUpdates[scope]
	return record, found, nil
}

func (t *memoryTx) PrimaryEmailUpdates() ([]PrimaryEmailUpdate, error) {
	if err := t.tx.Check(false); err != nil {
		return nil, err
	}
	result := make([]PrimaryEmailUpdate, 0, len(t.state.emailUpdates))
	for _, record := range t.state.emailUpdates {
		result = append(result, record)
	}
	return result, nil
}

func (t *memoryTx) PutPrimaryEmailUpdate(record PrimaryEmailUpdate) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	t.state.emailUpdates[record.Scope] = record
	return nil
}
