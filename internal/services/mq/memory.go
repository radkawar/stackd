package mq

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
)

type memoryKey struct {
	Scope
	ID string
}
type memoryState struct {
	brokers        map[memoryKey]BrokerRecord
	configurations map[memoryKey]ConfigurationRecord
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{brokers: map[memoryKey]BrokerRecord{}, configurations: map[memoryKey]ConfigurationRecord{}}
	return &MemoryRepository{memory.New(domain, initial, func(s memoryState) memoryState {
		s.brokers = maps.Clone(s.brokers)
		s.configurations = maps.Clone(s.configurations)
		return s
	})}
}
func (m *MemoryRepository) View(ctx context.Context, f func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, t *memory.Transaction) error { return f(memoryReader{s, t}) })
}
func (m *MemoryRepository) Update(ctx context.Context, f func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, t *memory.Transaction) error { return f(memoryWriter{memoryReader{s, t}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, f func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, t *memory.Transaction) error { return f(memoryWriter{memoryReader{s, t}}) })
}

type memoryReader struct {
	s *memoryState
	t *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.t.Context() }
func cloneBroker(v BrokerRecord) BrokerRecord {
	v.Tags = maps.Clone(v.Tags)
	v.Endpoint.CAPEM = slices.Clone(v.Endpoint.CAPEM)
	v.Users = slices.Clone(v.Users)
	for i := range v.Users {
		v.Users[i].Groups = slices.Clone(v.Users[i].Groups)
		v.Users[i].PendingGroups = slices.Clone(v.Users[i].PendingGroups)
	}
	v.ConfigurationHistory = slices.Clone(v.ConfigurationHistory)
	if v.PendingLogs != nil {
		pending := *v.PendingLogs
		v.PendingLogs = &pending
	}
	return v
}
func (r memoryReader) Broker(scope Scope, id string) (BrokerRecord, error) {
	if err := r.t.Check(false); err != nil {
		return BrokerRecord{}, err
	}
	v, ok := r.s.brokers[memoryKey{scope, id}]
	if !ok {
		return v, ErrNotFound
	}
	return cloneBroker(v), nil
}
func (r memoryReader) AllBrokers() ([]BrokerRecord, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	rows := make([]BrokerRecord, 0, len(r.s.brokers))
	for _, v := range r.s.brokers {
		rows = append(rows, cloneBroker(v))
	}
	slices.SortFunc(rows, func(a, b BrokerRecord) int { return cmp.Compare(a.ARN, b.ARN) })
	return rows, nil
}
func (w memoryWriter) PutBroker(v BrokerRecord) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	v = cloneBroker(v)
	for i := range v.Users {
		slices.Sort(v.Users[i].Groups)
		slices.Sort(v.Users[i].PendingGroups)
	}
	slices.SortFunc(v.Users, func(a, b UserRecord) int { return cmp.Compare(a.Username, b.Username) })
	w.s.brokers[memoryKey{v.Scope, v.ID}] = v
	return nil
}
func (w memoryWriter) DeleteBroker(scope Scope, id string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.brokers, memoryKey{scope, id})
	return nil
}

func cloneConfiguration(v ConfigurationRecord) ConfigurationRecord {
	v.Tags = maps.Clone(v.Tags)
	v.Revisions = slices.Clone(v.Revisions)
	return v
}

func (r memoryReader) Configuration(scope Scope, id string) (ConfigurationRecord, error) {
	if err := r.t.Check(false); err != nil {
		return ConfigurationRecord{}, err
	}
	v, ok := r.s.configurations[memoryKey{scope, id}]
	if !ok {
		return v, ErrNotFound
	}
	return cloneConfiguration(v), nil
}

func (r memoryReader) AllConfigurations() ([]ConfigurationRecord, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	rows := make([]ConfigurationRecord, 0, len(r.s.configurations))
	for _, v := range r.s.configurations {
		rows = append(rows, cloneConfiguration(v))
	}
	slices.SortFunc(rows, func(a, b ConfigurationRecord) int { return cmp.Compare(a.ARN, b.ARN) })
	return rows, nil
}

func (w memoryWriter) PutConfiguration(v ConfigurationRecord) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	v = cloneConfiguration(v)
	slices.SortFunc(v.Revisions, func(a, b ConfigurationRevisionRecord) int { return cmp.Compare(a.Revision, b.Revision) })
	w.s.configurations[memoryKey{v.Scope, v.ID}] = v
	return nil
}

func (w memoryWriter) DeleteConfiguration(scope Scope, id string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.configurations, memoryKey{scope, id})
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
