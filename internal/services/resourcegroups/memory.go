package resourcegroups

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/google/uuid"
	"stackd/storage/memory"
)

type memoryState struct {
	groups    map[string]Group
	groupings map[string]map[string]Grouping
	tasks     map[string]TagSyncTask
	applied   map[string]map[string]AppliedMembership
	accounts  map[Scope]LifecycleAccount
	snapshots map[string]LifecycleSnapshot
}

// Stored groups are immutable; reads and writes detach all mutable fields.
func cloneMemory(s memoryState) memoryState {
	return memoryState{groups: maps.Clone(s.groups), groupings: maps.Clone(s.groupings), tasks: maps.Clone(s.tasks), applied: maps.Clone(s.applied), accounts: maps.Clone(s.accounts), snapshots: maps.Clone(s.snapshots)}
}

func cloneStoredGroup(g Group) Group {
	g.Tags = maps.Clone(g.Tags)
	if g.Criticality != nil {
		g.Criticality = new(*g.Criticality)
	}
	if g.Query != nil {
		q := *g.Query
		if q.Query != nil {
			q.Query = new(*q.Query)
		}
		if q.Type != nil {
			q.Type = new(*q.Type)
		}
		g.Query = &q
	}
	return g
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	return &MemoryRepository{store: memory.New(domain, memoryState{groups: map[string]Group{}, groupings: map[string]map[string]Grouping{}, tasks: map[string]TagSyncTask{}, applied: map[string]map[string]AppliedMembership{}, accounts: map[Scope]LifecycleAccount{}, snapshots: map[string]LifecycleSnapshot{}}, cloneMemory)}
}

func (r *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return r.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (r *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return r.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}
func (r *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return r.store.Attempt(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

type memoryReader struct {
	state *memoryState
	tx    *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }
func (r memoryReader) findGroup(scope Scope, identifier string) (Group, bool) {
	if g, ok := r.state.groups[identifier]; ok && g.Scope == scope {
		return g, true
	}
	for _, g := range r.state.groups {
		if g.Scope == scope && g.Name == identifier {
			return g, true
		}
	}
	return Group{}, false
}
func (r memoryReader) Group(scope Scope, identifier string) (Group, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return Group{}, false, err
	}
	g, ok := r.findGroup(scope, identifier)
	return cloneStoredGroup(g), ok, nil
}
func (r memoryReader) Groups(scope Scope) ([]Group, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Group{}
	for _, g := range r.state.groups {
		if g.Scope == scope {
			out = append(out, cloneStoredGroup(g))
		}
	}
	slices.SortFunc(out, func(a, b Group) int { return strings.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (w memoryWriter) PutGroup(g Group) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for arn, existing := range w.state.groups {
		if arn != g.ARN && existing.Scope == g.Scope && existing.Name == g.Name {
			return errors.New("resource group name already exists")
		}
	}
	if existing, ok := w.state.groups[g.ARN]; ok && existing.Scope != g.Scope {
		return errors.New("resource group ARN belongs to another scope")
	}
	if old, ok := w.state.groups[g.ARN]; ok {
		g.Incarnation = old.Incarnation
		g.CloudFormationClaim = old.CloudFormationClaim
	} else {
		g.Incarnation = uuid.NewString()
	}
	w.state.groups[g.ARN] = cloneStoredGroup(g)
	return nil
}
func (w memoryWriter) DeleteGroup(scope Scope, identifier string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	g, ok := w.findGroup(scope, identifier)
	if !ok {
		return nil
	}
	delete(w.state.groups, g.ARN)
	delete(w.state.groupings, g.ARN)
	for arn, task := range w.state.tasks {
		if task.GroupARN == g.ARN {
			delete(w.state.tasks, arn)
			delete(w.state.applied, arn)
		}
	}
	return nil
}

var _ Repository = (*MemoryRepository)(nil)

func (r memoryReader) Groupings(arn string) ([]Grouping, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := slices.Collect(maps.Values(r.state.groupings[arn]))
	slices.SortFunc(rows, func(a, b Grouping) int { return strings.Compare(a.ResourceARN, b.ResourceARN) })
	return rows, nil
}

func (w memoryWriter) PutGrouping(g Grouping) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.state.groups[g.GroupARN]; !ok {
		return errors.New("resource group does not exist")
	}
	if g.Status == "" {
		g.Status = "SUCCESS"
	}
	rows := maps.Clone(w.state.groupings[g.GroupARN])
	if rows == nil {
		rows = map[string]Grouping{}
	}
	rows[g.ResourceARN] = g
	w.state.groupings[g.GroupARN] = rows
	return nil
}
