package sqs

import (
	"context"
	"maps"
	"slices"
	"time"

	"stackd/internal/awsctx"
	"stackd/storage/memory"
)

// MemoryRepository is a transactional process-local repository. It contains no
// authorization, queue validation, delivery scheduling, or cryptographic logic.
type MemoryRepository struct {
	store *memory.Store[memoryState]
}
type memoryState struct {
	queues   map[QueueKey]QueueRecord
	messages map[string]QueueMessages
	deleted  map[QueueKey]time.Time
	tasks    map[string]MoveTaskRecord
	metrics  map[MetricPublicationKey]map[metricSampleKey]int64
}

// NewMemoryRepository joins domain; nil constructs an independent domain.
func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{queues: make(map[QueueKey]QueueRecord), messages: make(map[string]QueueMessages), deleted: make(map[QueueKey]time.Time), tasks: make(map[string]MoveTaskRecord), metrics: make(map[MetricPublicationKey]map[metricSampleKey]int64)}
	return &MemoryRepository{store: memory.New(domain, initial, func(state memoryState) memoryState {
		return memoryState{queues: maps.Clone(state.queues), messages: maps.Clone(state.messages), deleted: maps.Clone(state.deleted), tasks: maps.Clone(state.tasks), metrics: cloneMetricSamples(state.metrics)}
	})}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(state *memoryState, tx *memory.Transaction) error {
		return fn(memoryReader{state: state, tx: tx})
	})
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(state *memoryState, tx *memory.Transaction) error {
		return fn(memoryTransaction{memoryReader{state: state, tx: tx}})
	})
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(state *memoryState, tx *memory.Transaction) error {
		return fn(memoryTransaction{memoryReader{state: state, tx: tx}})
	})
}

type memoryReader struct {
	state *memoryState
	tx    *memory.Transaction
}

func (r memoryReader) Context() context.Context { return r.tx.Context() }

func (r memoryReader) Queue(key QueueKey) (QueueRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return QueueRecord{}, err
	}

	q, ok := r.state.queues[key]
	if !ok {
		return QueueRecord{}, ErrNotFound
	}
	return cloneQueueRecord(q), nil
}
func (r memoryReader) Queues() ([]QueueRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}

	out := make([]QueueRecord, 0, len(r.state.queues))
	for _, q := range r.state.queues {
		out = append(out, cloneQueueRecord(q))
	}
	slices.SortFunc(out, func(a, b QueueRecord) int { return compareARN(privateKey(a.Key), privateKey(b.Key)) })
	return out, nil
}
func (r memoryReader) Messages(id string) (QueueMessages, error) {
	if err := r.tx.Check(false); err != nil {
		return QueueMessages{}, err
	}

	return cloneQueueMessages(r.state.messages[id]), nil
}
func (r memoryReader) DeletedAt(key QueueKey) (time.Time, error) {
	if err := r.tx.Check(false); err != nil {
		return time.Time{}, err
	}
	return r.state.deleted[key], nil
}
func (r memoryReader) MoveTasks() ([]MoveTaskRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}

	out := make([]MoveTaskRecord, 0, len(r.state.tasks))
	for _, task := range r.state.tasks {
		out = append(out, cloneMoveTask(task))
	}
	slices.SortFunc(out, func(a, b MoveTaskRecord) int {
		if a.Sequence < b.Sequence {
			return -1
		}
		if a.Sequence > b.Sequence {
			return 1
		}
		return 0
	})
	return out, nil
}

type memoryTransaction struct{ memoryReader }

func (t memoryTransaction) PutQueue(q QueueRecord) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	t.state.queues[q.Key] = cloneQueueRecord(q)
	return nil
}
func (t memoryTransaction) PutMessages(id string, m QueueMessages) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	t.state.messages[id] = cloneQueueMessages(m)
	return nil
}
func (t memoryTransaction) DeleteQueue(key QueueKey) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	q, ok := t.state.queues[key]
	if !ok {
		return ErrNotFound
	}
	delete(t.state.queues, key)
	delete(t.state.messages, q.ID)
	return nil
}
func (t memoryTransaction) SetDeletedAt(key QueueKey, at time.Time) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	t.state.deleted[key] = at
	return nil
}
func (t memoryTransaction) PutMoveTask(task MoveTaskRecord) error {
	if err := t.tx.Check(true); err != nil {
		return err
	}
	t.state.tasks[task.Handle] = cloneMoveTask(task)
	return nil
}
func cloneQueueRecord(q QueueRecord) QueueRecord {
	q.Configuration.PolicyPrincipals = maps.Clone(q.Configuration.PolicyPrincipals)
	q.Configuration.RedriveSources = slices.Clone(q.Configuration.RedriveSources)
	q.Tags = slices.Clone(q.Tags)
	q.ManagedEncryptionKey = slices.Clone(q.ManagedEncryptionKey)
	return q
}
func cloneQueueMessages(m QueueMessages) QueueMessages {
	m.Messages = slices.Clone(m.Messages)
	for i := range m.Messages {
		m.Messages[i].Data = slices.Clone(m.Messages[i].Data)
		m.Messages[i].EncryptedDataKey = slices.Clone(m.Messages[i].EncryptedDataKey)
	}
	m.Receipts = slices.Clone(m.Receipts)
	m.Deduplications = slices.Clone(m.Deduplications)
	m.Attempts = slices.Clone(m.Attempts)
	m.NoisyGroups = slices.Clone(m.NoisyGroups)
	for i := range m.Attempts {
		m.Attempts[i].MessageIDs = slices.Clone(m.Attempts[i].MessageIDs)
		m.Attempts[i].Handles = slices.Clone(m.Attempts[i].Handles)
		m.Attempts[i].Generations = slices.Clone(m.Attempts[i].Generations)
	}
	return m
}

func cloneMoveTask(task MoveTaskRecord) MoveTaskRecord {
	task.Caller = awsctx.Clone(task.Caller)
	return task
}
