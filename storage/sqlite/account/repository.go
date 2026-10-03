// Package account stores Account Management state in its own SQLite tables.
package account

import (
	"context"
	"database/sql"
	"errors"

	domain "stackd/storage/account"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/account/internal/sqlcgen"
)

// Repository joins related IAM and Organizations callbacks on the same database.
// The caller owns the database and must close its stack first.
type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }

func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		return fn(reader{ctx, sqlcgen.New(tx)})
	})
}

func (r *Repository) Update(ctx context.Context, fn func(domain.Writer) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx, sqlcgen.New(tx)}})
	})
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }

func (r reader) Region(key domain.RegionKey) (domain.RegionRecord, bool, error) {
	row, err := r.q.GetRegion(r.ctx, sqlcgen.GetRegionParams{Partition: key.Partition, Account: key.AccountID, Region: key.Region})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.RegionRecord{}, false, nil
	}
	if err != nil {
		return domain.RegionRecord{}, false, err
	}
	return domain.RegionRecord{Status: domain.RegionStatus(row.Status), Due: row.Due}, true, nil
}

func (w writer) PutRegion(key domain.RegionKey, record domain.RegionRecord) error {
	return w.q.PutRegion(w.ctx, sqlcgen.PutRegionParams{Partition: key.Partition, Account: key.AccountID, Region: key.Region, Status: string(record.Status), Due: record.Due})
}

func (r reader) Contact(sc domain.Scope) (domain.ContactInformation, bool, error) {
	row, err := r.q.GetContact(r.ctx, sqlcgen.GetContactParams{Partition: sc.Partition, Account: sc.AccountID})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ContactInformation{}, false, nil
	}
	if err != nil {
		return domain.ContactInformation{}, false, err
	}
	return domain.ContactInformation{FullName: row.FullName, AddressLine1: row.AddressLine1, City: row.City, PostalCode: row.PostalCode, CountryCode: row.CountryCode, PhoneNumber: row.PhoneNumber, AddressLine2: row.AddressLine2, AddressLine3: row.AddressLine3, StateOrRegion: row.StateOrRegion, DistrictOrCounty: row.DistrictOrCounty, CompanyName: row.CompanyName, WebsiteURL: row.WebsiteUrl}, true, nil
}

func (w writer) PutContact(sc domain.Scope, record domain.ContactInformation) error {
	return w.q.PutContact(w.ctx, sqlcgen.PutContactParams{Partition: sc.Partition, Account: sc.AccountID, FullName: record.FullName, AddressLine1: record.AddressLine1, City: record.City, PostalCode: record.PostalCode, CountryCode: record.CountryCode, PhoneNumber: record.PhoneNumber, AddressLine2: record.AddressLine2, AddressLine3: record.AddressLine3, StateOrRegion: record.StateOrRegion, DistrictOrCounty: record.DistrictOrCounty, CompanyName: record.CompanyName, WebsiteUrl: record.WebsiteURL})
}

func (r reader) AlternateContact(key domain.AlternateContactKey) (domain.AlternateContact, bool, error) {
	row, err := r.q.GetAlternateContact(r.ctx, sqlcgen.GetAlternateContactParams{Partition: key.Scope.Partition, Account: key.Scope.AccountID, ContactType: string(key.Type)})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AlternateContact{}, false, nil
	}
	if err != nil {
		return domain.AlternateContact{}, false, err
	}
	return domain.AlternateContact{Name: row.Name, Title: row.Title, EmailAddress: row.EmailAddress, PhoneNumber: row.PhoneNumber}, true, nil
}

func (w writer) PutAlternateContact(key domain.AlternateContactKey, record domain.AlternateContact) error {
	return w.q.PutAlternateContact(w.ctx, sqlcgen.PutAlternateContactParams{Partition: key.Scope.Partition, Account: key.Scope.AccountID, ContactType: string(key.Type), Name: record.Name, Title: record.Title, EmailAddress: record.EmailAddress, PhoneNumber: record.PhoneNumber})
}

func (w writer) DeleteAlternateContact(key domain.AlternateContactKey) error {
	return w.q.DeleteAlternateContact(w.ctx, sqlcgen.DeleteAlternateContactParams{Partition: key.Scope.Partition, Account: key.Scope.AccountID, ContactType: string(key.Type)})
}
