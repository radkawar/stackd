package cloudcontrol

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"stackd/internal/awsctx"
	"stackd/storage/memory"
)

type MemoryRepository struct {
	store *memory.Store[map[string]RequestRecord]
}

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(domain, map[string]RequestRecord{}, maps.Clone[map[string]RequestRecord])}
}
func (r *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return r.store.View(ctx, func(s *map[string]RequestRecord, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (r *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return r.store.Update(ctx, func(s *map[string]RequestRecord, tx *memory.Transaction) error {
		return fn(memoryWriter{memoryReader{s, tx}})
	})
}

type memoryReader struct {
	state *map[string]RequestRecord
	tx    *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context  { return r.tx.Context() }
func cloneRequest(v RequestRecord) RequestRecord { v.Caller = awsctx.Clone(v.Caller); return v }
func (r memoryReader) Request(token string) (RequestRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return RequestRecord{}, err
	}
	v, ok := (*r.state)[token]
	if !ok {
		return RequestRecord{}, ErrNotFound
	}
	return cloneRequest(v), nil
}
func (r memoryReader) Requests(scope Scope) ([]RequestRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []RequestRecord{}
	for _, v := range *r.state {
		if v.Scope == scope {
			out = append(out, cloneRequest(v))
		}
	}
	slices.SortFunc(out, func(a, b RequestRecord) int { return cmp.Compare(a.Token, b.Token) })
	return out, nil
}
func (r memoryReader) NextRequest() (RequestRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return RequestRecord{}, false, err
	}
	var next RequestRecord
	found := false
	for _, v := range *r.state {
		if !active(v.Status) {
			continue
		}
		if !found || v.Due.Before(next.Due) || v.Due.Equal(next.Due) && v.Token < next.Token {
			next, found = v, true
		}
	}
	return cloneRequest(next), found, nil
}
func (w memoryWriter) PutRequest(v RequestRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	(*w.state)[v.Token] = cloneRequest(v)
	return nil
}
