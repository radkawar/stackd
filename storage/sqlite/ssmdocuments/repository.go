// Package ssmdocuments persists immutable document source and typed version metadata.
package ssmdocuments

import (
	"context"
	"database/sql"
	"errors"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/ssmdocuments/internal/sqlcgen"
	domain "stackd/storage/ssmdocuments"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
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
func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func (r reader) row(k domain.Key) (sqlcgen.SsmDocument, error) {
	v, e := r.q.GetDocument(r.ctx, sqlcgen.GetDocumentParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	return v, missing(e)
}
func (r reader) record(v sqlcgen.SsmDocument) (domain.Record, error) {
	out := domain.Record{Key: domain.Key{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, Type: v.DocumentType, SchemaName: v.SchemaName, SchemaVersion: v.SchemaVersion, SchemaDocumentID: v.SchemaDocumentUuid, DocumentID: v.DocumentUuid, DefaultVersion: v.DefaultVersion, LatestVersion: v.LatestVersion, NextVersion: v.NextVersion, Tags: map[string]string{}}
	tags, e := r.q.ListTags(r.ctx, v.ID)
	if e != nil {
		return out, e
	}
	for _, t := range tags {
		out.Tags[t.TagKey] = t.Value
	}
	shares, e := r.q.ListShares(r.ctx, v.ID)
	if e != nil {
		return out, e
	}
	if len(shares) != 0 {
		out.Shares = make(map[string]string, len(shares))
	}
	for _, share := range shares {
		out.Shares[share.AccountID] = share.VersionSelector
	}
	return out, nil
}
func (r reader) Document(k domain.Key) (domain.Record, error) {
	v, e := r.row(k)
	if e != nil {
		return domain.Record{}, e
	}
	return r.record(v)
}
func (r reader) Documents(sc domain.Scope) ([]domain.Record, error) {
	rows, e := r.q.ListDocuments(r.ctx, sqlcgen.ListDocumentsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Record, 0, len(rows))
	for _, v := range rows {
		record, e := r.record(v)
		if e != nil {
			return nil, e
		}
		out = append(out, record)
	}
	return out, nil
}
func (r reader) SharedDocuments(sc domain.Scope) ([]domain.Record, error) {
	rows, err := r.q.ListSharedDocuments(r.ctx, sqlcgen.ListSharedDocumentsParams{Partition: sc.Partition, Region: sc.Region, RecipientAccountID: sc.AccountID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Record, 0, len(rows))
	for _, row := range rows {
		record, err := r.record(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func version(k domain.Key, v sqlcgen.SsmDocumentVersion) domain.Version {
	return domain.Version{Key: domain.VersionKey{Document: k, Version: v.Version}, Content: v.Content, Format: v.Format, Hash: v.Hash, VersionName: v.VersionName, DisplayName: v.DisplayName, TargetType: v.TargetType, Created: v.Created, Status: v.Status, ReadyAt: v.ReadyAt}
}
func (r reader) Version(k domain.VersionKey) (domain.Version, error) {
	d, e := r.row(k.Document)
	if e != nil {
		return domain.Version{}, e
	}
	v, e := r.q.GetVersion(r.ctx, sqlcgen.GetVersionParams{DocumentID: d.ID, Version: k.Version})
	return version(k.Document, v), missing(e)
}
func (r reader) Versions(k domain.Key) ([]domain.Version, error) {
	d, e := r.row(k)
	if e != nil {
		return nil, e
	}
	rows, e := r.q.ListVersions(r.ctx, d.ID)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Version, 0, len(rows))
	for _, v := range rows {
		out = append(out, version(k, v))
	}
	return out, nil
}
func (w writer) PutDocument(v domain.Record) error {
	id, e := w.q.PutDocument(w.ctx, sqlcgen.PutDocumentParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name, DocumentUuid: v.DocumentID, DefaultVersion: v.DefaultVersion, LatestVersion: v.LatestVersion, NextVersion: v.NextVersion, DocumentType: v.Type, SchemaName: v.SchemaName, SchemaVersion: v.SchemaVersion, SchemaDocumentUuid: v.SchemaDocumentID})
	if e != nil {
		return e
	}
	if e = w.q.ClearTags(w.ctx, id); e != nil {
		return e
	}
	for k, value := range v.Tags {
		if e = w.q.InsertTag(w.ctx, sqlcgen.InsertTagParams{DocumentID: id, TagKey: k, Value: value}); e != nil {
			return e
		}
	}
	if e = w.q.ClearShares(w.ctx, id); e != nil {
		return e
	}
	for account, selector := range v.Shares {
		if e = w.q.InsertShare(w.ctx, sqlcgen.InsertShareParams{DocumentID: id, AccountID: account, VersionSelector: selector}); e != nil {
			return e
		}
	}
	return nil
}
func (w writer) DeleteDocument(k domain.Key) error {
	return w.q.DeleteDocument(w.ctx, sqlcgen.DeleteDocumentParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
func (w writer) InsertVersion(v domain.Version) error {
	d, e := w.row(v.Key.Document)
	if e != nil {
		return e
	}
	return w.q.InsertVersion(w.ctx, sqlcgen.InsertVersionParams{DocumentID: d.ID, Version: v.Key.Version, Content: v.Content, Format: v.Format, Hash: v.Hash, VersionName: v.VersionName, DisplayName: v.DisplayName, TargetType: v.TargetType, Created: v.Created, Status: v.Status, ReadyAt: v.ReadyAt})
}
func (w writer) DeleteVersion(k domain.VersionKey) error {
	d, e := w.row(k.Document)
	if e != nil {
		return e
	}
	return w.q.DeleteVersion(w.ctx, sqlcgen.DeleteVersionParams{DocumentID: d.ID, Version: k.Version})
}

func (r reader) NextActivation() (domain.Activation, error) {
	row, err := r.q.NextActivation(r.ctx)
	if err != nil {
		return domain.Activation{}, missing(err)
	}
	key := domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name}
	return domain.Activation{Key: domain.VersionKey{Document: key, Version: row.Version}, DocumentID: row.DocumentUuid, Due: row.ReadyAt}, nil
}

func (w writer) ActivateVersion(k domain.VersionKey) error {
	d, err := w.row(k.Document)
	if err != nil {
		return err
	}
	return w.q.ActivateVersion(w.ctx, sqlcgen.ActivateVersionParams{DocumentID: d.ID, Version: k.Version})
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
