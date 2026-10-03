package ecs

import (
	"cmp"
	"context"
	"maps"
	"slices"
	api "stackd/internal/awsapi/ecs"
	"stackd/storage/memory"
	"strings"
)

type memoryState struct {
	clusters         map[ClusterKey]ClusterRecord
	definitions      map[TaskDefinitionKey]TaskDefinitionRecord
	revisions        map[FamilyKey]int32
	tags             map[TagKey]TagRecord
	tasks            map[TaskKey]TaskRecord
	taskRuns         map[TaskRunKey]TaskRunRecord
	services         map[ServiceKey]ServiceRecord
	serviceRevisions map[ServiceRevisionKey]ServiceRevisionRecord
	metrics          map[MetricPublicationKey]map[metricSampleKey]MetricSample
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{
		clusters: map[ClusterKey]ClusterRecord{}, definitions: map[TaskDefinitionKey]TaskDefinitionRecord{},
		revisions: map[FamilyKey]int32{}, tags: map[TagKey]TagRecord{},
		tasks: map[TaskKey]TaskRecord{}, taskRuns: map[TaskRunKey]TaskRunRecord{},
		services:         map[ServiceKey]ServiceRecord{},
		serviceRevisions: map[ServiceRevisionKey]ServiceRevisionRecord{},
		metrics:          map[MetricPublicationKey]map[metricSampleKey]MetricSample{},
	}
	return &MemoryRepository{memory.New(domain, initial, func(v memoryState) memoryState {
		return memoryState{
			clusters: maps.Clone(v.clusters), definitions: maps.Clone(v.definitions),
			revisions: maps.Clone(v.revisions), tags: maps.Clone(v.tags),
			tasks: maps.Clone(v.tasks), taskRuns: maps.Clone(v.taskRuns),
			services:         maps.Clone(v.services),
			serviceRevisions: maps.Clone(v.serviceRevisions),
			metrics:          maps.Clone(v.metrics),
		}
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
func cloneClusterRecord(v ClusterRecord) ClusterRecord {
	v.Data = api.CloneCluster(v.Data)
	v.CreateInput = api.CloneCreateClusterRequest(v.CreateInput)
	return v
}
func cloneTaskDefinitionRecord(v TaskDefinitionRecord) TaskDefinitionRecord {
	v.Data = api.CloneTaskDefinition(v.Data)
	return v
}
func (r memoryReader) Cluster(k ClusterKey) (ClusterRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ClusterRecord{}, err
	}
	v, ok := r.s.clusters[k]
	if !ok {
		return ClusterRecord{}, ErrNotFound
	}
	return cloneClusterRecord(v), nil
}
func (r memoryReader) Clusters(q ClusterQuery) ([]ClusterRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ClusterRecord{}
	for k, v := range r.s.clusters {
		if k.Scope == q.Scope && k.Name > q.After && (q.IncludeInactive || value(v.Data.Status) == "ACTIVE") {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b ClusterRecord) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	for i := range out {
		out[i] = cloneClusterRecord(out[i])
	}
	return out, nil
}
func (r memoryReader) ActiveClusterKeys(partition, accountID string) ([]ClusterKey, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []ClusterKey
	for key, record := range r.s.clusters {
		if key.Partition == partition && key.AccountID == accountID && value(record.Data.Status) == "ACTIVE" {
			out = append(out, key)
		}
	}
	slices.SortFunc(out, func(a, b ClusterKey) int {
		return cmp.Or(strings.Compare(a.Region, b.Region), strings.Compare(a.Name, b.Name))
	})
	return out, nil
}
func (r memoryReader) TaskDefinition(k TaskDefinitionKey) (TaskDefinitionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TaskDefinitionRecord{}, err
	}
	v, ok := r.s.definitions[k]
	if !ok {
		return TaskDefinitionRecord{}, ErrNotFound
	}
	return cloneTaskDefinitionRecord(v), nil
}
func (r memoryReader) TaskDefinitions(q TaskDefinitionQuery) ([]TaskDefinitionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []TaskDefinitionRecord{}
	for k, v := range r.s.definitions {
		if k.Scope != q.Scope || q.Family != "" && k.Family != q.Family || !strings.HasPrefix(k.Family, q.FamilyPrefix) || q.Status != "" && value(v.Data.Status) != q.Status {
			continue
		}
		if q.AfterFamily != "" {
			c := strings.Compare(k.Family, q.AfterFamily)
			if c == 0 {
				c = cmp.Compare(k.Revision, q.AfterRevision)
			}
			if !q.Descending && c <= 0 || q.Descending && c >= 0 {
				continue
			}
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b TaskDefinitionRecord) int {
		c := strings.Compare(a.Key.Family, b.Key.Family)
		if c == 0 {
			c = cmp.Compare(a.Key.Revision, b.Key.Revision)
		}
		if q.Descending {
			return -c
		}
		return c
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	for i := range out {
		out[i] = cloneTaskDefinitionRecord(out[i])
	}
	return out, nil
}
func (r memoryReader) Tags(k TagKey) (TagRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TagRecord{}, err
	}
	v, ok := r.s.tags[k]
	if !ok {
		return TagRecord{Key: k}, ErrNotFound
	}
	v.Tags = api.CloneTags(v.Tags)
	return v, nil
}
func (w memoryWriter) PutCluster(v ClusterRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.clusters[v.Key] = cloneClusterRecord(v)
	return nil
}
func (w memoryWriter) PutTaskDefinition(v TaskDefinitionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.definitions[v.Key] = cloneTaskDefinitionRecord(v)
	return nil
}
func (w memoryWriter) DeleteTaskDefinition(k TaskDefinitionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.definitions, k)
	delete(w.s.tags, TagKey{Scope: k.Scope, ResourceARN: k.ARN()})
	return nil
}
func (w memoryWriter) NextTaskDefinitionRevision(k FamilyKey) (int32, error) {
	if err := w.tx.Check(true); err != nil {
		return 0, err
	}
	n := w.s.revisions[k]
	if n == 2147483647 {
		return 0, failure("ClientException", "Task definition revision limit exceeded.")
	}
	n++
	w.s.revisions[k] = n
	return n, nil
}
func (w memoryWriter) PutTags(v TagRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Tags = api.CloneTags(v.Tags)
	w.s.tags[v.Key] = v
	return nil
}
