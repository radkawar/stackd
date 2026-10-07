package cloudformation

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"stackd/internal/awsctx"
	"stackd/storage/memory"
)

type resourceKey struct {
	stack, logical string
	generation     uint64
}
type eventKey struct {
	stack    string
	sequence uint64
}
type exportKey struct {
	scope Scope
	name  string
}
type memoryState struct {
	stacks     map[string]StackRecord
	resources  map[resourceKey]ResourceRecord
	events     map[eventKey]EventRecord
	operations map[string]OperationRecord
	changeSets map[string]ChangeSetRecord
	exports    map[exportKey]ExportRecord
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{store: memory.New(d, memoryState{
		stacks: make(map[string]StackRecord), resources: make(map[resourceKey]ResourceRecord),
		events: make(map[eventKey]EventRecord), operations: make(map[string]OperationRecord),
		changeSets: make(map[string]ChangeSetRecord), exports: make(map[exportKey]ExportRecord),
	}, func(s memoryState) memoryState {
		s.stacks = maps.Clone(s.stacks)
		s.resources = maps.Clone(s.resources)
		s.events = maps.Clone(s.events)
		s.operations = maps.Clone(s.operations)
		s.changeSets = maps.Clone(s.changeSets)
		s.exports = maps.Clone(s.exports)
		return s
	})}
}

func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }

func cloneDocument(v any) any {
	switch v := v.(type) {
	case Properties:
		return cloneProperties(v)
	case map[string]any:
		if v == nil {
			return v
		}
		out := make(map[string]any, len(v))
		for key, value := range v {
			out[key] = cloneDocument(value)
		}
		return out
	case []any:
		if v == nil {
			return v
		}
		out := make([]any, len(v))
		for i, value := range v {
			out[i] = cloneDocument(value)
		}
		return out
	default:
		return v
	}
}
func cloneProperties(v Properties) Properties {
	if v == nil {
		return nil
	}
	out := make(Properties, len(v))
	for key, value := range v {
		out[key] = cloneDocument(value)
	}
	return out
}
func cloneStack(v StackRecord) StackRecord {
	v.Parameters = maps.Clone(v.Parameters)
	v.ResolvedParameters = maps.Clone(v.ResolvedParameters)
	v.Tags = maps.Clone(v.Tags)
	v.Capabilities = slices.Clone(v.Capabilities)
	v.Outputs = maps.Clone(v.Outputs)
	v.Imports = slices.Clone(v.Imports)
	if v.Deleted != nil {
		v.Deleted = new(*v.Deleted)
	}
	return v
}
func cloneResource(v ResourceRecord) ResourceRecord {
	v.Properties = cloneProperties(v.Properties)
	v.EventProperties = cloneProperties(v.EventProperties)
	v.DynamicReferences = maps.Clone(v.DynamicReferences)
	v.Attributes = cloneDocument(v.Attributes).(map[string]any)
	return v
}
func cloneEvent(v EventRecord) EventRecord {
	v.Properties = cloneProperties(v.Properties)
	return v
}
func cloneOperation(v OperationRecord) OperationRecord {
	v.Parameters = maps.Clone(v.Parameters)
	v.ResolvedParameters = maps.Clone(v.ResolvedParameters)
	v.Tags = maps.Clone(v.Tags)
	v.Capabilities = slices.Clone(v.Capabilities)
	v.Caller = awsctx.Clone(v.Caller)
	v.Steps = slices.Clone(v.Steps)
	for i := range v.Steps {
		v.Steps[i].Before = cloneResource(v.Steps[i].Before)
		v.Steps[i].After = cloneResource(v.Steps[i].After)
		v.Steps[i].Restore = cloneResource(v.Steps[i].Restore)
	}
	return v
}
func cloneChangeSet(v ChangeSetRecord) ChangeSetRecord {
	v.Parameters = maps.Clone(v.Parameters)
	v.ResolvedParameters = maps.Clone(v.ResolvedParameters)
	v.Tags = maps.Clone(v.Tags)
	v.Capabilities = slices.Clone(v.Capabilities)
	v.Changes = slices.Clone(v.Changes)
	return v
}

func (r memoryReader) Stack(id string) (StackRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return StackRecord{}, err
	}
	v, ok := r.s.stacks[id]
	if !ok {
		return StackRecord{}, ErrNotFound
	}
	return cloneStack(v), nil
}
func (r memoryReader) Stacks(scope Scope) ([]StackRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []StackRecord{}
	for _, v := range r.s.stacks {
		if v.Scope == scope {
			out = append(out, cloneStack(v))
		}
	}
	slices.SortFunc(out, func(a, b StackRecord) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (r memoryReader) Resources(stack string) ([]ResourceRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ResourceRecord{}
	for _, v := range r.s.resources {
		if v.StackID == stack {
			out = append(out, cloneResource(v))
		}
	}
	slices.SortFunc(out, func(a, b ResourceRecord) int {
		if n := cmp.Compare(a.LogicalID, b.LogicalID); n != 0 {
			return n
		}
		return cmp.Compare(a.Generation, b.Generation)
	})
	return out, nil
}
func (r memoryReader) Events(stack string) ([]EventRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []EventRecord{}
	for _, v := range r.s.events {
		if v.StackID == stack {
			out = append(out, cloneEvent(v))
		}
	}
	slices.SortFunc(out, func(a, b EventRecord) int { return cmp.Compare(b.Sequence, a.Sequence) })
	return out, nil
}
func (r memoryReader) Operation(id string) (OperationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return OperationRecord{}, err
	}
	v, ok := r.s.operations[id]
	if !ok {
		return OperationRecord{}, ErrNotFound
	}
	return cloneOperation(v), nil
}
func (r memoryReader) NextOperation() (OperationRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return OperationRecord{}, false, err
	}
	var next OperationRecord
	found := false
	for _, v := range r.s.operations {
		if v.Phase == "DONE" {
			continue
		}
		if !found || v.Due.Before(next.Due) || (v.Due.Equal(next.Due) && v.ID < next.ID) {
			next, found = v, true
		}
	}
	if !found {
		return OperationRecord{}, false, nil
	}
	return cloneOperation(next), true, nil
}
func (r memoryReader) ChangeSet(id string) (ChangeSetRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ChangeSetRecord{}, err
	}
	v, ok := r.s.changeSets[id]
	if !ok {
		return ChangeSetRecord{}, ErrNotFound
	}
	return cloneChangeSet(v), nil
}
func (r memoryReader) ChangeSets(stack string) ([]ChangeSetRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ChangeSetRecord{}
	for _, v := range r.s.changeSets {
		if v.StackID == stack {
			out = append(out, cloneChangeSet(v))
		}
	}
	slices.SortFunc(out, func(a, b ChangeSetRecord) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (r memoryReader) Exports(scope Scope) ([]ExportRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ExportRecord{}
	for _, v := range r.s.exports {
		if v.Scope == scope {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b ExportRecord) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}
func (w memoryWriter) PutStack(v StackRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.stacks[v.ID] = cloneStack(v)
	return nil
}
func (w memoryWriter) PutResource(v ResourceRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.resources[resourceKey{v.StackID, v.LogicalID, v.Generation}] = cloneResource(v)
	return nil
}
func (w memoryWriter) PutEvent(v EventRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.events[eventKey{v.StackID, v.Sequence}] = cloneEvent(v)
	return nil
}
func (w memoryWriter) PutOperation(v OperationRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.operations[v.ID] = cloneOperation(v)
	return nil
}
func (w memoryWriter) PutChangeSet(v ChangeSetRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.changeSets[v.ID] = cloneChangeSet(v)
	return nil
}
func (w memoryWriter) DeleteChangeSet(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.changeSets, id)
	return nil
}
func (w memoryWriter) PutExport(v ExportRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.exports[exportKey{v.Scope, v.Name}] = v
	return nil
}
func (w memoryWriter) DeleteExport(scope Scope, name string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.exports, exportKey{scope, name})
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
