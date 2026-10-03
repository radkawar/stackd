package acm

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
)

type tokenKey struct{ partition, account, domain string }
type receiptKey struct {
	Scope
	token string
}
type memoryState struct {
	certificates map[string]CertificateRecord
	tokens       map[tokenKey]ValidationToken
	receipts     map[receiptKey]Receipt
	authority    *Authority
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{certificates: map[string]CertificateRecord{}, tokens: map[tokenKey]ValidationToken{}, receipts: map[receiptKey]Receipt{}}, func(v memoryState) memoryState {
		v.certificates = maps.Clone(v.certificates)
		v.tokens = maps.Clone(v.tokens)
		v.receipts = maps.Clone(v.receipts)
		return v
	})}
}
func (m *MemoryRepository) View(c context.Context, f func(Reader) error) error {
	return m.store.View(c, func(s *memoryState, t *memory.Transaction) error { return f(memoryReader{s, t}) })
}
func (m *MemoryRepository) Update(c context.Context, f func(Transaction) error) error {
	return m.store.Update(c, func(s *memoryState, t *memory.Transaction) error { return f(memoryWriter{memoryReader{s, t}}) })
}
func (m *MemoryRepository) Attempt(c context.Context, f func(Transaction) error) error {
	return m.store.Attempt(c, func(s *memoryState, t *memory.Transaction) error { return f(memoryWriter{memoryReader{s, t}}) })
}

type memoryReader struct {
	s *memoryState
	t *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.t.Context() }
func cloneCertificate(v CertificateRecord) CertificateRecord {
	v.Validations = slices.Clone(v.Validations)
	v.Tags = maps.Clone(v.Tags)
	v.CertificatePEM = slices.Clone(v.CertificatePEM)
	v.ChainPEM = slices.Clone(v.ChainPEM)
	v.PrivateKeyPEM = slices.Clone(v.PrivateKeyPEM)
	return v
}
func (r memoryReader) Certificate(arn string) (CertificateRecord, error) {
	if e := r.t.Check(false); e != nil {
		return CertificateRecord{}, e
	}
	v, ok := r.s.certificates[arn]
	if !ok {
		return CertificateRecord{}, ErrNotFound
	}
	return cloneCertificate(v), nil
}
func (r memoryReader) Certificates() ([]CertificateRecord, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := make([]CertificateRecord, 0, len(r.s.certificates))
	for _, v := range r.s.certificates {
		out = append(out, cloneCertificate(v))
	}
	slices.SortFunc(out, func(a, b CertificateRecord) int { return cmp.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (r memoryReader) Token(p, a, d string) (ValidationToken, error) {
	if e := r.t.Check(false); e != nil {
		return ValidationToken{}, e
	}
	v, ok := r.s.tokens[tokenKey{p, a, d}]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) Receipt(s Scope, t string) (Receipt, error) {
	if e := r.t.Check(false); e != nil {
		return Receipt{}, e
	}
	v, ok := r.s.receipts[receiptKey{s, t}]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) Authority() (Authority, error) {
	if e := r.t.Check(false); e != nil {
		return Authority{}, e
	}
	if r.s.authority == nil {
		return Authority{}, ErrNotFound
	}
	return Authority{slices.Clone(r.s.authority.CertificatePEM), slices.Clone(r.s.authority.PrivateKeyPEM)}, nil
}
func (w memoryWriter) PutCertificate(v CertificateRecord) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.certificates[v.ARN] = cloneCertificate(v)
	return nil
}
func (w memoryWriter) DeleteCertificate(arn string) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.certificates, arn)
	return nil
}
func (w memoryWriter) PutToken(v ValidationToken) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.tokens[tokenKey{v.Partition, v.AccountID, v.Domain}] = v
	return nil
}
func (w memoryWriter) PutReceipt(v Receipt) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.receipts[receiptKey{v.Scope, v.Token}] = v
	return nil
}
func (w memoryWriter) PutAuthority(v Authority) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.authority = &Authority{slices.Clone(v.CertificatePEM), slices.Clone(v.PrivateKeyPEM)}
	return nil
}
func (r memoryReader) CertificateState(arn string) (CertificateState, error) {
	if e := r.t.Check(false); e != nil {
		return CertificateState{}, e
	}
	c, ok := r.s.certificates[arn]
	if !ok {
		return CertificateState{}, ErrNotFound
	}
	return CertificateState{Scope: c.Scope, ID: c.ID, Status: c.Status, NotBefore: c.NotBefore, NotAfter: c.NotAfter, MaterialVersion: c.MaterialVersion}, nil
}
