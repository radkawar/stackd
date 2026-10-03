// Package acm retains certificates, validation tokens and the local CA in shared SQLite transactions.
package acm

import (
	"context"
	"database/sql"
	"errors"
	domain "stackd/storage/acm"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/acm/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return fn(reader{ctx, sqlcgen.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}
func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func missing(e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return e
}
func (r reader) Certificate(arn string) (domain.CertificateRecord, error) {
	row, e := r.q.GetCertificate(r.ctx, arn)
	if e != nil {
		return domain.CertificateRecord{}, missing(e)
	}
	return r.certificate(row)
}
func (r reader) Certificates() ([]domain.CertificateRecord, error) {
	rows, e := r.q.ListCertificates(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.CertificateRecord, 0, len(rows))
	for _, row := range rows {
		v, e := r.certificate(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) certificate(row sqlcgen.AcmCertificate) (domain.CertificateRecord, error) {
	v := domain.CertificateRecord{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ARN: row.Arn, ID: row.ID, Domain: row.Domain, Status: row.Status, Type: row.Type, KeyAlgorithm: row.KeyAlgorithm, Transparency: row.Transparency, ExportOption: row.ExportOption, Created: row.Created, Issued: row.Issued, Imported: row.Imported, NotBefore: row.NotBefore, NotAfter: row.NotAfter, ValidationDeadline: row.ValidationDeadline, NextCheck: row.NextCheck, RenewalUpdated: row.RenewalUpdated, Version: uint64(row.Version), MaterialVersion: uint64(row.MaterialVersion), RenewalStatus: row.RenewalStatus, Exported: row.Exported, CertificatePEM: row.CertificatePem, ChainPEM: row.ChainPem, PrivateKeyPEM: row.PrivateKeyPem, Tags: map[string]string{}}
	validations, e := r.q.ListValidations(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, a := range validations {
		v.Validations = append(v.Validations, domain.Validation{Domain: a.Domain, Name: a.Name, Value: a.Value, Status: a.Status})
	}
	tags, e := r.q.ListTags(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, t := range tags {
		v.Tags[t.Key] = t.Value
	}
	return v, nil
}
func nonnil(v []byte) []byte {
	if v == nil {
		return []byte{}
	}
	return v
}
func (w writer) PutCertificate(v domain.CertificateRecord) error {
	e := w.q.PutCertificate(w.ctx, sqlcgen.PutCertificateParams{Arn: v.ARN, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.ID, Domain: v.Domain, Status: v.Status, Type: v.Type, KeyAlgorithm: v.KeyAlgorithm, Transparency: v.Transparency, ExportOption: v.ExportOption, Created: v.Created, Issued: v.Issued, Imported: v.Imported, NotBefore: v.NotBefore, NotAfter: v.NotAfter, ValidationDeadline: v.ValidationDeadline, NextCheck: v.NextCheck, RenewalUpdated: v.RenewalUpdated, Version: int64(v.Version), MaterialVersion: int64(v.MaterialVersion), RenewalStatus: v.RenewalStatus, Exported: v.Exported, CertificatePem: nonnil(v.CertificatePEM), ChainPem: nonnil(v.ChainPEM), PrivateKeyPem: nonnil(v.PrivateKeyPEM)})
	if e != nil {
		return e
	}
	if e = w.q.DeleteValidations(w.ctx, v.ARN); e != nil {
		return e
	}
	for i, a := range v.Validations {
		if e = w.q.PutValidation(w.ctx, sqlcgen.PutValidationParams{CertificateArn: v.ARN, Position: int64(i), Domain: a.Domain, Name: a.Name, Value: a.Value, Status: a.Status}); e != nil {
			return e
		}
	}
	if e = w.q.DeleteTags(w.ctx, v.ARN); e != nil {
		return e
	}
	for k, value := range v.Tags {
		if e = w.q.PutTag(w.ctx, sqlcgen.PutTagParams{CertificateArn: v.ARN, Key: k, Value: value}); e != nil {
			return e
		}
	}
	return nil
}
func (w writer) DeleteCertificate(arn string) error { return w.q.DeleteCertificate(w.ctx, arn) }
func (r reader) Token(p, a, d string) (domain.ValidationToken, error) {
	v, e := r.q.GetToken(r.ctx, sqlcgen.GetTokenParams{Partition: p, AccountID: a, Domain: d})
	return domain.ValidationToken{Partition: v.Partition, AccountID: v.AccountID, Domain: v.Domain, Name: v.Name, Value: v.Value}, missing(e)
}
func (w writer) PutToken(v domain.ValidationToken) error {
	return w.q.PutToken(w.ctx, sqlcgen.PutTokenParams{Partition: v.Partition, AccountID: v.AccountID, Domain: v.Domain, Name: v.Name, Value: v.Value})
}
func (r reader) Authority() (domain.Authority, error) {
	v, e := r.q.GetAuthority(r.ctx)
	return domain.Authority{CertificatePEM: v.CertificatePem, PrivateKeyPEM: v.PrivateKeyPem}, missing(e)
}
func (w writer) PutAuthority(v domain.Authority) error {
	return w.q.PutAuthority(w.ctx, sqlcgen.PutAuthorityParams{CertificatePem: v.CertificatePEM, PrivateKeyPem: v.PrivateKeyPEM})
}
func (r reader) Receipt(s domain.Scope, t string) (domain.Receipt, error) {
	v, e := r.q.GetReceipt(r.ctx, sqlcgen.GetReceiptParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: t})
	return domain.Receipt{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Token: v.Token, ARN: v.Arn, Expires: v.Expires}, missing(e)
}
func (w writer) PutReceipt(v domain.Receipt) error {
	return w.q.PutReceipt(w.ctx, sqlcgen.PutReceiptParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Token: v.Token, Arn: v.ARN, Expires: v.Expires})
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}

func (r reader) CertificateState(arn string) (domain.CertificateState, error) {
	v, e := r.q.GetCertificateState(r.ctx, arn)
	return domain.CertificateState{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ID: v.ID, Status: v.Status, NotBefore: v.NotBefore, NotAfter: v.NotAfter, MaterialVersion: uint64(v.MaterialVersion)}, missing(e)
}
