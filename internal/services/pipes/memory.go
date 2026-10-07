package pipes

import (
	"context"
	"maps"
	"slices"
	api "stackd/internal/awsapi/pipes"
	"stackd/storage/memory"
)

type memoryState struct {
	pipes       map[Key]PipeRecord
	checkpoints map[[2]string]Checkpoint
	work        map[string]Work
	kafka       map[string]KafkaIdentity
}
type MemoryRepository struct {
	store *memory.Store[memoryState]
}

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{map[Key]PipeRecord{}, map[[2]string]Checkpoint{}, map[string]Work{}, map[string]KafkaIdentity{}}, func(v memoryState) memoryState {
		v.pipes = maps.Clone(v.pipes)
		v.checkpoints = maps.Clone(v.checkpoints)
		v.work = maps.Clone(v.work)
		v.kafka = maps.Clone(v.kafka)
		return v
	})}
}
func (m *MemoryRepository) View(c context.Context, f func(Reader) error) error {
	return m.store.View(c, func(s *memoryState, t *memory.Transaction) error {
		return f(memoryReader{s, t})
	})
}
func (m *MemoryRepository) Update(c context.Context, f func(Transaction) error) error {
	return m.store.Update(c, func(s *memoryState, t *memory.Transaction) error {
		return f(memoryWriter{memoryReader{s, t}})
	})
}
func (m *MemoryRepository) Attempt(c context.Context, f func(Transaction) error) error {
	return m.store.Attempt(c, func(s *memoryState, t *memory.Transaction) error {
		return f(memoryWriter{memoryReader{s, t}})
	})
}

type memoryReader struct {
	s *memoryState
	t *memory.Transaction
}
type memoryWriter struct {
	memoryReader
}

func (r memoryReader) Context() context.Context {
	return r.t.Context()
}
func clonePipe(p PipeRecord) PipeRecord {
	p.Tags = maps.Clone(p.Tags)
	p.Source.Filters = slices.Clone(p.Source.Filters)
	p.Source.Kafka.BootstrapServers = slices.Clone(p.Source.Kafka.BootstrapServers)
	if p.Source.StartingTime != nil {
		p.Source.StartingTime = new(*p.Source.StartingTime)
	}
	p.Target = api.ClonePipeTargetParameters(p.Target)
	p.EnrichmentHTTP = cloneEnrichmentHTTP(p.EnrichmentHTTP)
	p.Encrypted = cloneEncrypted(p.Encrypted)
	return p
}
func cloneWork(w Work) Work {
	w.Event = slices.Clone(w.Event)
	return w
}
func (r memoryReader) Pipe(k Key) (PipeRecord, error) {
	if e := r.t.Check(false); e != nil {
		return PipeRecord{}, e
	}
	p, ok := r.s.pipes[k]
	if !ok {
		return PipeRecord{}, ErrNotFound
	}
	return clonePipe(p), nil
}
func (r memoryReader) PipeByID(id string) (PipeRecord, error) {
	if e := r.t.Check(false); e != nil {
		return PipeRecord{}, e
	}
	for _, p := range r.s.pipes {
		if p.ID == id {
			return clonePipe(p), nil
		}
	}
	return PipeRecord{}, ErrNotFound
}
func (r memoryReader) Pipes() ([]PipeRecord, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	v := []PipeRecord{}
	for _, p := range r.s.pipes {
		v = append(v, clonePipe(p))
	}
	slices.SortFunc(v, func(a, b PipeRecord) int {
		if a.Key.ARN() < b.Key.ARN() {
			return -1
		}
		if a.Key.ARN() > b.Key.ARN() {
			return 1
		}
		return 0
	})
	return v, nil
}
func (r memoryReader) Checkpoints(id string) ([]Checkpoint, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	v := []Checkpoint{}
	for _, c := range r.s.checkpoints {
		if c.PipeID == id {
			v = append(v, c)
		}
	}
	slices.SortFunc(v, func(a, b Checkpoint) int {
		if a.ShardID < b.ShardID {
			return -1
		}
		if a.ShardID > b.ShardID {
			return 1
		}
		return 0
	})
	return v, nil
}
func (r memoryReader) Work(id string) ([]Work, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	v := []Work{}
	for _, w := range r.s.work {
		if w.PipeID == id {
			v = append(v, cloneWork(w))
		}
	}
	slices.SortFunc(v, func(a, b Work) int {
		if a.Ordinal < b.Ordinal {
			return -1
		}
		if a.Ordinal > b.Ordinal {
			return 1
		}
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return v, nil
}
func (r memoryReader) KafkaIdentity(id string) (KafkaIdentity, error) {
	if err := r.t.Check(false); err != nil {
		return KafkaIdentity{}, err
	}
	return r.s.kafka[id], nil
}
func (r memoryWriter) PutKafkaIdentity(id string, identity KafkaIdentity) error {
	if err := r.t.Check(true); err != nil {
		return err
	}
	if _, err := r.PipeByID(id); err != nil {
		return err
	}
	if _, exists := r.s.kafka[id]; !exists {
		r.s.kafka[id] = identity
	}
	return nil
}
func (r memoryWriter) PutPipe(p PipeRecord) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	if old, ok := r.s.pipes[p.Key]; ok && old.ID == p.ID {
		p.CFNOwner = old.CFNOwner
	}
	r.s.pipes[p.Key] = clonePipe(Stored(p))
	return nil
}
func (r memoryWriter) PutCheckpoint(c Checkpoint) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	r.s.checkpoints[[2]string{c.PipeID, c.ShardID}] = c
	return nil
}
func (r memoryWriter) PutWork(w Work) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	r.s.work[w.ID] = cloneWork(w)
	return nil
}
func (r memoryWriter) DeleteWork(id string) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	delete(r.s.work, id)
	return nil
}
func (r memoryWriter) DeletePipe(k Key) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	p, ok := r.s.pipes[k]
	if !ok {
		return ErrNotFound
	}
	delete(r.s.pipes, k)
	delete(r.s.kafka, p.ID)
	for k, c := range r.s.checkpoints {
		if c.PipeID == p.ID {
			delete(r.s.checkpoints, k)
		}
	}
	for k, w := range r.s.work {
		if w.PipeID == p.ID {
			delete(r.s.work, k)
		}
	}
	return nil
}
