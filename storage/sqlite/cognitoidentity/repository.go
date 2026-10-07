// Package cognitoidentity stores typed identity pools and unique provider bindings.
package cognitoidentity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	domain "stackd/storage/cognitoidentity"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/cognitoidentity/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

// New borrows the shared database without taking ownership of its lifecycle.
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
func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func decodePool(row sqlcgen.CognitoidentityPool, err error) (domain.PoolRecord, error) {
	if err != nil {
		return domain.PoolRecord{}, missing(err)
	}
	p := domain.PoolRecord{Key: domain.PoolKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.PoolID}, Name: row.Name, AllowUnauthenticated: row.AllowUnauthenticated != 0, AllowClassic: row.AllowClassic != 0,
		Owner: domain.ResourceOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}}
	for _, field := range []struct {
		raw    []byte
		target any
	}{{row.Providers, &p.Providers}, {row.Tags, &p.Tags}, {row.Roles, &p.Roles}, {row.Mappings, &p.Mappings}, {row.PrincipalTagMaps, &p.PrincipalTagMaps}} {
		if err := json.Unmarshal(field.raw, field.target); err != nil {
			return domain.PoolRecord{}, err
		}
	}
	return p, nil
}
func (r reader) Pool(k domain.PoolKey) (domain.PoolRecord, error) {
	return decodePool(r.q.GetPool(r.ctx, sqlcgen.GetPoolParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID}))
}
func (r reader) PoolByID(p, g, id string) (domain.PoolRecord, error) {
	return decodePool(r.q.PoolByID(r.ctx, sqlcgen.PoolByIDParams{Partition: p, Region: g, PoolID: id}))
}
func (r reader) PoolByOwner(scope domain.Scope, owner domain.ResourceOwner) (domain.PoolRecord, error) {
	return decodePool(r.q.PoolByOwner(r.ctx, sqlcgen.PoolByOwnerParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, OwnerStackID: owner.StackID, OwnerLogicalID: owner.LogicalID, OwnerToken: owner.Token}))
}
func (r reader) Pools(scope domain.Scope) ([]domain.PoolRecord, error) {
	rows, err := r.q.ListPools(r.ctx, sqlcgen.ListPoolsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PoolRecord, 0, len(rows))
	for _, row := range rows {
		p, err := decodePool(row, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
func (w writer) PutPool(p domain.PoolRecord) error {
	// The owner claim is written with a new row; upserts never rewrite it.
	row := sqlcgen.PutPoolParams{Partition: p.Key.Partition, AccountID: p.Key.AccountID, Region: p.Key.Region, PoolID: p.Key.ID, Name: p.Name,
		OwnerStackID: p.Owner.StackID, OwnerLogicalID: p.Owner.LogicalID, OwnerToken: p.Owner.Token}
	if p.AllowUnauthenticated {
		row.AllowUnauthenticated = 1
	}
	if p.AllowClassic {
		row.AllowClassic = 1
	}
	for _, field := range []struct {
		source any
		target *[]byte
	}{{p.Providers, &row.Providers}, {p.Tags, &row.Tags}, {p.Roles, &row.Roles}, {p.Mappings, &row.Mappings}, {p.PrincipalTagMaps, &row.PrincipalTagMaps}} {
		raw, err := json.Marshal(field.source)
		if err != nil {
			return err
		}
		*field.target = raw
	}
	return w.q.PutPool(w.ctx, row)
}
func (w writer) DeletePool(k domain.PoolKey) error {
	return w.q.DeletePool(w.ctx, sqlcgen.DeletePoolParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID})
}
func (r reader) decodeIdentity(row sqlcgen.CognitoidentityIdentity, err error) (domain.IdentityRecord, error) {
	if err != nil {
		return domain.IdentityRecord{}, missing(err)
	}
	id := domain.IdentityRecord{Pool: domain.PoolKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.PoolID}, ID: row.IdentityID, Created: row.Created.UTC(), Modified: row.Modified.UTC()}
	logins, err := r.q.ListLogins(r.ctx, sqlcgen.ListLoginsParams{Partition: row.Partition, Region: row.Region, IdentityID: row.IdentityID})
	if err != nil {
		return id, err
	}
	id.Logins = make([]domain.Login, 0, len(logins))
	for _, login := range logins {
		id.Logins = append(id.Logins, domain.Login{Provider: login.Provider, Subject: login.Subject})
	}
	return id, nil
}
func (r reader) Identity(p, g, id string) (domain.IdentityRecord, error) {
	return r.decodeIdentity(r.q.GetIdentity(r.ctx, sqlcgen.GetIdentityParams{Partition: p, Region: g, IdentityID: id}))
}
func (r reader) IdentityByLogin(p domain.PoolKey, l domain.Login) (domain.IdentityRecord, error) {
	return r.decodeIdentity(r.q.IdentityByLogin(r.ctx, sqlcgen.IdentityByLoginParams{Partition: p.Partition, Region: p.Region, PoolID: p.ID, Provider: l.Provider, Subject: l.Subject}))
}
func (r reader) Identities(k domain.PoolKey) ([]domain.IdentityRecord, error) {
	rows, err := r.q.ListIdentities(r.ctx, sqlcgen.ListIdentitiesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.IdentityRecord, 0, len(rows))
	for _, row := range rows {
		id, err := r.decodeIdentity(row, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}
func (w writer) PutIdentity(id domain.IdentityRecord) error {
	if err := w.q.PutIdentity(w.ctx, sqlcgen.PutIdentityParams{Partition: id.Pool.Partition, AccountID: id.Pool.AccountID, Region: id.Pool.Region, PoolID: id.Pool.ID, IdentityID: id.ID, Created: id.Created.UTC(), Modified: id.Modified.UTC()}); err != nil {
		return err
	}
	if err := w.q.DeleteLogins(w.ctx, sqlcgen.DeleteLoginsParams{Partition: id.Pool.Partition, Region: id.Pool.Region, IdentityID: id.ID}); err != nil {
		return err
	}
	for _, login := range id.Logins {
		if err := w.q.PutLogin(w.ctx, sqlcgen.PutLoginParams{Partition: id.Pool.Partition, Region: id.Pool.Region, PoolID: id.Pool.ID, IdentityID: id.ID, Provider: login.Provider, Subject: login.Subject}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteIdentity(p, g, id string) error {
	return w.q.DeleteIdentity(w.ctx, sqlcgen.DeleteIdentityParams{Partition: p, Region: g, IdentityID: id})
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
