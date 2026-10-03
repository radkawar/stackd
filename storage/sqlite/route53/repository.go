// Package route53 persists normalized hosted zones in the shared transaction domain.
package route53

import (
	"context"
	"database/sql"
	"errors"
	domain "stackd/storage/route53"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/route53/internal/sqlcgen"
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
func missing(e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return e
}
func (r reader) Zone(id string) (domain.Zone, error) {
	row, e := r.q.GetZone(r.ctx, id)
	if e != nil {
		return domain.Zone{}, missing(e)
	}
	return r.zone(row)
}
func (r reader) Zones() ([]domain.Zone, error) {
	rows, e := r.q.ListZones(r.ctx)
	if e != nil {
		return nil, e
	}
	zones := make([]domain.Zone, 0, len(rows))
	for _, row := range rows {
		z, e := r.zone(row)
		if e != nil {
			return nil, e
		}
		zones = append(zones, z)
	}
	return zones, nil
}
func (r reader) zone(row sqlcgen.Route53Zone) (domain.Zone, error) {
	z := domain.Zone{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID}, ID: row.ID, Name: row.Name, CallerReference: row.CallerReference, Comment: row.Comment, Created: row.Created}
	records, e := r.q.ListRecordSets(r.ctx, z.ID)
	if e != nil {
		return z, e
	}
	values, e := r.q.ListRecordValues(r.ctx, z.ID)
	if e != nil {
		return z, e
	}
	type key struct{ name, kind, id string }
	index := make(map[key]int, len(records))
	z.Records = make([]domain.RecordSet, len(records))
	for i, row := range records {
		rr := domain.RecordSet{Name: row.Name, Type: row.Type, Identifier: row.Identifier, TTL: row.Ttl, Weighted: row.Weighted, Weight: row.Weight, MultiValue: row.MultiValue}
		if row.AliasZoneID != "" {
			rr.Alias = &domain.AliasTarget{HostedZoneID: row.AliasZoneID, DNSName: row.AliasDnsName}
		}
		z.Records[i] = rr
		index[key{row.Name, row.Type, row.Identifier}] = i
	}
	for _, v := range values {
		i, ok := index[key{v.Name, v.Type, v.Identifier}]
		if !ok {
			return z, errors.New("record value has no record set")
		}
		z.Records[i].Values = append(z.Records[i].Values, v.Value)
	}
	return z, nil
}
func (w writer) PutZone(z domain.Zone) error {
	if e := w.q.PutZone(w.ctx, sqlcgen.PutZoneParams{ID: z.ID, Partition: z.Partition, AccountID: z.AccountID, Name: z.Name, CallerReference: z.CallerReference, Comment: z.Comment, Created: z.Created}); e != nil {
		return e
	}
	if e := w.q.DeleteRecordSets(w.ctx, z.ID); e != nil {
		return e
	}
	for _, rr := range z.Records {
		row := sqlcgen.PutRecordSetParams{ZoneID: z.ID, Name: rr.Name, Type: rr.Type, Identifier: rr.Identifier, Ttl: rr.TTL, Weighted: rr.Weighted, Weight: rr.Weight, MultiValue: rr.MultiValue}
		if rr.Alias != nil {
			row.AliasZoneID = rr.Alias.HostedZoneID
			row.AliasDnsName = rr.Alias.DNSName
		}
		if e := w.q.PutRecordSet(w.ctx, row); e != nil {
			return e
		}
		for i, v := range rr.Values {
			if e := w.q.PutRecordValue(w.ctx, sqlcgen.PutRecordValueParams{ZoneID: z.ID, Name: rr.Name, Type: rr.Type, Identifier: rr.Identifier, Position: int64(i), Value: v}); e != nil {
				return e
			}
		}
	}
	return nil
}
func (w writer) DeleteZone(id string) error { return w.q.DeleteZone(w.ctx, id) }
func (r reader) Change(id string) (domain.Change, error) {
	row, e := r.q.GetChange(r.ctx, id)
	return domain.Change{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID}, ID: row.ID, ZoneID: row.ZoneID, Comment: row.Comment, Submitted: row.Submitted, Ready: row.Ready}, missing(e)
}
func (w writer) PutChange(c domain.Change) error {
	return w.q.PutChange(w.ctx, sqlcgen.PutChangeParams{ID: c.ID, Partition: c.Partition, AccountID: c.AccountID, ZoneID: c.ZoneID, Comment: c.Comment, Submitted: c.Submitted, Ready: c.Ready})
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
