package codepipeline

import (
	"cmp"
	"context"
	"maps"
	"slices"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/storage/memory"
	"time"
)

type pipelineKey struct {
	Scope
	Name string
}
type definitionKey struct {
	Scope
	Incarnation string
	Version     int32
}
type executionKey struct {
	Scope
	ID string
}
type sourcePollKey struct {
	Scope
	Incarnation, StageName, ActionName string
}
type memoryState struct {
	pipelines      map[pipelineKey]Pipeline
	definitions    map[definitionKey]Definition
	executions     map[executionKey]Execution
	sourcePolls    map[sourcePollKey]SourcePoll
	invocationJobs map[executionKey]InvocationJob
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{pipelines: map[pipelineKey]Pipeline{}, definitions: map[definitionKey]Definition{}, executions: map[executionKey]Execution{}, sourcePolls: map[sourcePollKey]SourcePoll{}, invocationJobs: map[executionKey]InvocationJob{}}, func(s memoryState) memoryState {
		s.pipelines = maps.Clone(s.pipelines)
		s.definitions = maps.Clone(s.definitions)
		s.executions = maps.Clone(s.executions)
		s.sourcePolls = maps.Clone(s.sourcePolls)
		s.invocationJobs = maps.Clone(s.invocationJobs)
		return s
	})}
}
func (r *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return r.store.View(ctx, func(s *memoryState, t *memory.Transaction) error { return fn(memoryReader{s, t}) })
}
func (r *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return r.store.Update(ctx, func(s *memoryState, t *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, t}}) })
}
func (r *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return r.store.Attempt(ctx, func(s *memoryState, t *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, t}}) })
}

type memoryReader struct {
	s *memoryState
	t *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.t.Context() }
func (r memoryReader) Pipelines(sc Scope) ([]Pipeline, error) {
	out := []Pipeline{}
	for k, v := range r.s.pipelines {
		if k.Scope == sc {
			out = append(out, clonePipeline(v))
		}
	}
	slices.SortFunc(out, func(a, b Pipeline) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}
func (r memoryReader) Definition(sc Scope, id string, v int32) (Definition, bool, error) {
	d, ok := r.s.definitions[definitionKey{sc, id, v}]
	d.Declaration = CloneDeclaration(d.Declaration)
	return d, ok, nil
}
func (r memoryReader) Executions(sc Scope, id string) ([]Execution, error) {
	out := []Execution{}
	for _, e := range r.s.executions {
		if e.Scope == sc && (id == "" || e.Incarnation == id) {
			out = append(out, cloneExecution(e))
		}
	}
	sortExecutions(out)
	return out, nil
}
func (r memoryReader) PendingExecutions() ([]Execution, error) {
	out := []Execution{}
	for _, e := range r.s.executions {
		if !e.Due.IsZero() {
			out = append(out, cloneExecution(e))
		}
	}
	sortExecutions(out)
	return out, nil
}
func (w memoryWriter) PutPipeline(p Pipeline) error {
	w.s.pipelines[pipelineKey{p.Scope, p.Name}] = clonePipeline(p)
	return nil
}
func (w memoryWriter) PutDefinition(d Definition) error {
	d.Declaration = CloneDeclaration(d.Declaration)
	w.s.definitions[definitionKey{d.Scope, d.Incarnation, int32(value(d.Declaration.Version))}] = d
	return nil
}
func (w memoryWriter) PutExecution(e Execution) error {
	w.s.executions[executionKey{e.Scope, e.ID}] = cloneExecution(e)
	return nil
}
func (r memoryReader) SourcePolls(sc Scope, id string) ([]SourcePoll, error) {
	out := []SourcePoll{}
	for _, p := range r.s.sourcePolls {
		if p.Scope == sc && p.Incarnation == id {
			out = append(out, p)
		}
	}
	sortSourcePolls(out)
	return out, nil
}
func (r memoryReader) PendingSourcePolls() ([]SourcePoll, error) {
	out := []SourcePoll{}
	for _, p := range r.s.sourcePolls {
		if !p.Due.IsZero() {
			out = append(out, p)
		}
	}
	sortSourcePolls(out)
	return out, nil
}
func sortSourcePolls(out []SourcePoll) {
	slices.SortFunc(out, func(a, b SourcePoll) int {
		if n := cmp.Compare(a.StageName, b.StageName); n != 0 {
			return n
		}
		return cmp.Compare(a.ActionName, b.ActionName)
	})
}
func (w memoryWriter) PutSourcePoll(p SourcePoll) error {
	w.s.sourcePolls[sourcePollKey{p.Scope, p.Incarnation, p.StageName, p.ActionName}] = p
	return nil
}
func (w memoryWriter) DeleteSourcePolls(sc Scope, id string) error {
	for k := range w.s.sourcePolls {
		if k.Scope == sc && k.Incarnation == id {
			delete(w.s.sourcePolls, k)
		}
	}
	return nil
}
func (w memoryWriter) DeletePipeline(sc Scope, name string) error {
	key := pipelineKey{sc, name}
	p, ok := w.s.pipelines[key]
	if !ok {
		return nil
	}
	delete(w.s.pipelines, key)
	for k, e := range w.s.executions {
		if e.Scope == sc && e.Incarnation == p.Incarnation && !e.Due.IsZero() {
			e.Due = time.Time{}
			e.Generation++
			w.s.executions[k] = e
		}
	}
	return w.DeleteSourcePolls(sc, p.Incarnation)
}
func clonePipeline(v Pipeline) Pipeline {
	v.Tags = maps.Clone(v.Tags)
	v.Transitions = slices.Clone(v.Transitions)
	return v
}
func cloneExecution(v Execution) Execution {
	v.SourceOverrides = slices.Clone(v.SourceOverrides)
	for i := range v.SourceOverrides {
		o := &v.SourceOverrides[i]
		o.ActionName = copyPtr(o.ActionName)
		o.RevisionType = copyPtr(o.RevisionType)
		o.RevisionValue = copyPtr(o.RevisionValue)
	}
	v.Variables = slices.Clone(v.Variables)
	for i := range v.Variables {
		v.Variables[i].Name = copyPtr(v.Variables[i].Name)
		v.Variables[i].ResolvedValue = copyPtr(v.Variables[i].ResolvedValue)
	}
	v.Revisions = slices.Clone(v.Revisions)
	v.Actions = slices.Clone(v.Actions)
	for i := range v.Actions {
		v.Actions[i].InputArtifacts = slices.Clone(v.Actions[i].InputArtifacts)
		v.Actions[i].ResolvedConfiguration = maps.Clone(v.Actions[i].ResolvedConfiguration)
		v.Actions[i].OutputVariables = maps.Clone(v.Actions[i].OutputVariables)
		v.Actions[i].OutputArtifacts = slices.Clone(v.Actions[i].OutputArtifacts)
	}
	return v
}
func sortExecutions(out []Execution) {
	slices.SortFunc(out, func(a, b Execution) int {
		if n := a.StartedAt.Compare(b.StartedAt); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Sequence, b.Sequence); n != 0 {
			return n
		}
		return cmp.Compare(a.ID, b.ID)
	})
}
func copyPtr[T any](v *T) *T {
	if v == nil {
		return nil
	}
	return new(*v)
}

// CloneDeclaration copies the admitted provider declaration, including mutable
// leaves. Admission rejects fields without an execution/storage owner.
func CloneDeclaration(v api.PipelineDeclaration) api.PipelineDeclaration {
	v.Name = copyPtr(v.Name)
	v.RoleArn = copyPtr(v.RoleArn)
	v.Version = copyPtr(v.Version)
	v.PipelineType = copyPtr(v.PipelineType)
	v.ExecutionMode = copyPtr(v.ExecutionMode)
	v.Variables = slices.Clone(v.Variables)
	for i := range v.Variables {
		v.Variables[i].Name = copyPtr(v.Variables[i].Name)
		v.Variables[i].DefaultValue = copyPtr(v.Variables[i].DefaultValue)
		v.Variables[i].Description = copyPtr(v.Variables[i].Description)
	}
	if v.ArtifactStore != nil {
		x := *v.ArtifactStore
		x.Location = copyPtr(x.Location)
		x.Type = copyPtr(x.Type)
		if x.EncryptionKey != nil {
			e := *x.EncryptionKey
			e.Id = copyPtr(e.Id)
			e.Type = copyPtr(e.Type)
			x.EncryptionKey = &e
		}
		v.ArtifactStore = &x
	}
	v.Stages = slices.Clone(v.Stages)
	for i := range v.Stages {
		st := &v.Stages[i]
		st.Name = copyPtr(st.Name)
		st.Actions = slices.Clone(st.Actions)
		for j := range st.Actions {
			a := &st.Actions[j]
			a.Name = copyPtr(a.Name)
			a.Namespace = copyPtr(a.Namespace)
			a.Region = copyPtr(a.Region)
			a.RoleArn = copyPtr(a.RoleArn)
			a.RunOrder = copyPtr(a.RunOrder)
			a.TimeoutInMinutes = copyPtr(a.TimeoutInMinutes)
			if a.ActionTypeId != nil {
				t := *a.ActionTypeId
				t.Category = copyPtr(t.Category)
				t.Owner = copyPtr(t.Owner)
				t.Provider = copyPtr(t.Provider)
				t.Version = copyPtr(t.Version)
				a.ActionTypeId = &t
			}
			a.Configuration = maps.Clone(a.Configuration)
			a.InputArtifacts = slices.Clone(a.InputArtifacts)
			for k := range a.InputArtifacts {
				a.InputArtifacts[k].Name = copyPtr(a.InputArtifacts[k].Name)
			}
			a.OutputArtifacts = slices.Clone(a.OutputArtifacts)
			for k := range a.OutputArtifacts {
				a.OutputArtifacts[k].Name = copyPtr(a.OutputArtifacts[k].Name)
			}
		}
	}
	return v
}
