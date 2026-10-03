package stepfunctions

import (
	"context"
	"maps"

	"stackd/storage/memory"
)

type memoryHistoryKey struct {
	Execution ExecutionKey
	ID        int64
}

type memoryTokenKey struct {
	Scope
	Token string
}

type memoryState struct {
	machines   map[MachineKey]MachineRecord
	revisions  map[RevisionKey]RevisionRecord
	versions   map[VersionKey]VersionRecord
	aliases    map[AliasKey]AliasRecord
	activities map[ActivityKey]ActivityRecord
	executions map[ExecutionKey]ExecutionRecord
	redrives   map[ExecutionKey][]RedriveRequest
	frames     map[FrameKey]FrameRecord
	tasks      map[TaskKey]TaskRecord
	tokens     map[memoryTokenKey]TaskKey
	history    map[memoryHistoryKey]HistoryRecord
	mapRuns    map[MapRunKey]MapRunRecord
	mapFiles   map[MapRunKey][]MapResultFile
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{
		machines:   map[MachineKey]MachineRecord{},
		revisions:  map[RevisionKey]RevisionRecord{},
		versions:   map[VersionKey]VersionRecord{},
		aliases:    map[AliasKey]AliasRecord{},
		activities: map[ActivityKey]ActivityRecord{},
		executions: map[ExecutionKey]ExecutionRecord{},
		redrives:   map[ExecutionKey][]RedriveRequest{},
		frames:     map[FrameKey]FrameRecord{},
		tasks:      map[TaskKey]TaskRecord{},
		tokens:     map[memoryTokenKey]TaskKey{},
		history:    map[memoryHistoryKey]HistoryRecord{},
		mapRuns:    map[MapRunKey]MapRunRecord{},
		mapFiles:   map[MapRunKey][]MapResultFile{},
	}
	return &MemoryRepository{store: memory.New(domain, initial, func(s memoryState) memoryState {
		s.machines = maps.Clone(s.machines)
		s.revisions = maps.Clone(s.revisions)
		s.versions = maps.Clone(s.versions)
		s.aliases = maps.Clone(s.aliases)
		s.activities = maps.Clone(s.activities)
		s.executions = maps.Clone(s.executions)
		s.redrives = maps.Clone(s.redrives)
		s.frames = maps.Clone(s.frames)
		s.tasks = maps.Clone(s.tasks)
		s.tokens = maps.Clone(s.tokens)
		s.history = maps.Clone(s.history)
		s.mapRuns = maps.Clone(s.mapRuns)
		s.mapFiles = maps.Clone(s.mapFiles)
		return s
	})}
}

func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}

func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}

type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }

var _ Repository = (*MemoryRepository)(nil)
var _ Transaction = memoryWriter{}
