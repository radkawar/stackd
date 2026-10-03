package resourcegroupstaggingapi

import (
	"context"
	"maps"
	"slices"
	"strings"

	"stackd/internal/awsctx"
	"stackd/storage/memory"
)

type memoryState struct {
	memberships map[Membership]struct{}
	reports     map[Scope]Report
}

func cloneMemory(s memoryState) memoryState {
	out := memoryState{memberships: maps.Clone(s.memberships), reports: maps.Clone(s.reports)}
	for key, report := range out.reports {
		report.Caller = awsctx.Clone(report.Caller)
		out.reports[key] = report
	}
	return out
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	return &MemoryRepository{store: memory.New(domain, memoryState{memberships: map[Membership]struct{}{}, reports: map[Scope]Report{}}, cloneMemory)}
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
func (r memoryReader) Memberships(scope Scope, service string) ([]Membership, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Membership{}
	for m := range r.state.memberships {
		if m.Scope == scope && (service == "" || m.Service == service) {
			out = append(out, m)
		}
	}
	slices.SortFunc(out, func(a, b Membership) int { return strings.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (w memoryWriter) PutMembership(m Membership) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.memberships[m] = struct{}{}
	return nil
}
func (w memoryWriter) DeleteMembership(m Membership) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.memberships, m)
	return nil
}
func (r memoryReader) Report(scope Scope) (Report, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return Report{}, false, err
	}
	report, ok := r.state.reports[scope]
	report.Caller = awsctx.Clone(report.Caller)
	return report, ok, nil
}
func (r memoryReader) NextReport() (Report, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return Report{}, false, err
	}
	var next Report
	found := false
	for _, report := range r.state.reports {
		if report.Status != "RUNNING" {
			continue
		}
		if !found || report.Due.Before(next.Due) || report.Due.Equal(next.Due) && reportKey(report.Scope) < reportKey(next.Scope) {
			next = report
			found = true
		}
	}
	next.Caller = awsctx.Clone(next.Caller)
	return next, found, nil
}
func (w memoryWriter) PutReport(report Report) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	report.Caller = awsctx.Clone(report.Caller)
	w.state.reports[report.Scope] = report
	return nil
}
