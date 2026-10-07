// Package identitystore persists directory state in the shared SQLite transaction domain.
package identitystore

import (
	"context"
	"database/sql"
	"errors"
	d "stackd/storage/identitystore"
	"stackd/storage/sqlite"
	q "stackd/storage/sqlite/identitystore/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, fn func(d.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return fn(reader{ctx, q.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, fn func(d.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, q.New(tx)}}) })
}
func (r *Repository) Attempt(ctx context.Context, fn func(d.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, q.New(tx)}}) })
}

type reader struct {
	ctx context.Context
	q   *q.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func missing(e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return d.ErrNotFound
	}
	return e
}
func (r reader) Store(id string) (d.Store, error) {
	v, e := r.q.GetStore(r.ctx, id)
	return d.Store{ID: v.StoreID, Scope: d.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}}, missing(e)
}
func (w writer) PutStore(v d.Store) error {
	return w.q.PutStore(w.ctx, q.PutStoreParams{StoreID: v.ID, Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region})
}
func (r reader) user(v q.IdentitystoreUser) (d.User, error) {
	out := d.User{StoreID: v.StoreID, ID: v.ID, UserName: v.UserName, DisplayName: v.DisplayName, Name: d.Name{Formatted: v.NameFormatted, FamilyName: v.NameFamily, GivenName: v.NameGiven, MiddleName: v.NameMiddle, HonorificPrefix: v.NamePrefix, HonorificSuffix: v.NameSuffix}, NickName: v.NickName, ProfileURL: v.ProfileUrl, Title: v.Title, UserType: v.UserType, PreferredLanguage: v.PreferredLanguage, Locale: v.Locale, Timezone: v.Timezone, Birthdate: v.Birthdate, Website: v.Website}
	rows, e := r.q.ListEmails(r.ctx, q.ListEmailsParams{StoreID: v.StoreID, UserID: v.ID})
	if e != nil {
		return d.User{}, e
	}
	for _, email := range rows {
		out.Emails = append(out.Emails, d.Email{Value: email.Value, Type: email.Type, Primary: email.IsPrimary != 0})
	}
	return out, nil
}
func (r reader) User(k d.Key) (d.User, error) {
	v, e := r.q.GetUser(r.ctx, q.GetUserParams{StoreID: k.StoreID, ID: k.ID})
	if e != nil {
		return d.User{}, missing(e)
	}
	return r.user(v)
}
func (r reader) UserByName(store, name string) (d.User, error) {
	v, e := r.q.GetUserByName(r.ctx, q.GetUserByNameParams{StoreID: store, UserName: name})
	if e != nil {
		return d.User{}, missing(e)
	}
	return r.user(v)
}
func (r reader) Users(store string) ([]d.User, error) {
	rows, e := r.q.ListUsers(r.ctx, store)
	if e != nil {
		return nil, e
	}
	out := make([]d.User, 0, len(rows))
	for _, v := range rows {
		u, e := r.user(v)
		if e != nil {
			return nil, e
		}
		out = append(out, u)
	}
	return out, nil
}
func (w writer) PutUser(v d.User) error {
	if e := w.q.PutUser(w.ctx, q.PutUserParams{StoreID: v.StoreID, ID: v.ID, UserName: v.UserName, DisplayName: v.DisplayName, NameFormatted: v.Name.Formatted, NameFamily: v.Name.FamilyName, NameGiven: v.Name.GivenName, NameMiddle: v.Name.MiddleName, NamePrefix: v.Name.HonorificPrefix, NameSuffix: v.Name.HonorificSuffix, NickName: v.NickName, ProfileUrl: v.ProfileURL, Title: v.Title, UserType: v.UserType, PreferredLanguage: v.PreferredLanguage, Locale: v.Locale, Timezone: v.Timezone, Birthdate: v.Birthdate, Website: v.Website}); e != nil {
		return e
	}
	if e := w.q.DeleteEmails(w.ctx, q.DeleteEmailsParams{StoreID: v.StoreID, UserID: v.ID}); e != nil {
		return e
	}
	for i, vv := range v.Emails {
		var primary int64
		if vv.Primary {
			primary = 1
		}
		if e := w.q.PutEmail(w.ctx, q.PutEmailParams{StoreID: v.StoreID, UserID: v.ID, Ordinal: int64(i), Value: vv.Value, Type: vv.Type, IsPrimary: primary}); e != nil {
			return e
		}
	}
	return nil
}
func (w writer) DeleteUser(k d.Key) error {
	return w.q.DeleteUser(w.ctx, q.DeleteUserParams{StoreID: k.StoreID, ID: k.ID})
}
func group(v q.IdentitystoreGroup) d.Group {
	return d.Group{StoreID: v.StoreID, ID: v.ID, DisplayName: v.DisplayName, Description: v.Description, CloudFormationOwner: v.CloudformationOwner}
}
func (r reader) Group(k d.Key) (d.Group, error) {
	v, e := r.q.GetGroup(r.ctx, q.GetGroupParams{StoreID: k.StoreID, ID: k.ID})
	return group(v), missing(e)
}
func (r reader) GroupByName(store, name string) (d.Group, error) {
	v, e := r.q.GetGroupByName(r.ctx, q.GetGroupByNameParams{StoreID: store, DisplayName: name})
	return group(v), missing(e)
}
func (r reader) Groups(store string) ([]d.Group, error) {
	rows, e := r.q.ListGroups(r.ctx, store)
	out := make([]d.Group, 0, len(rows))
	for _, v := range rows {
		out = append(out, group(v))
	}
	return out, e
}
func (w writer) PutGroup(v d.Group) error {
	return w.q.PutGroup(w.ctx, q.PutGroupParams{StoreID: v.StoreID, ID: v.ID, DisplayName: v.DisplayName, Description: v.Description, CloudformationOwner: v.CloudFormationOwner})
}
func (w writer) DeleteGroup(k d.Key) error {
	return w.q.DeleteGroup(w.ctx, q.DeleteGroupParams{StoreID: k.StoreID, ID: k.ID})
}
func membership(v q.IdentitystoreMembership) d.Membership {
	return d.Membership{StoreID: v.StoreID, ID: v.ID, UserID: v.UserID, GroupID: v.GroupID, CloudFormationOwner: v.CloudformationOwner}
}
func (r reader) Membership(k d.Key) (d.Membership, error) {
	v, e := r.q.GetMembership(r.ctx, q.GetMembershipParams{StoreID: k.StoreID, ID: k.ID})
	return membership(v), missing(e)
}
func (r reader) MembershipFor(store, user, group string) (d.Membership, error) {
	v, e := r.q.GetMembershipFor(r.ctx, q.GetMembershipForParams{StoreID: store, UserID: user, GroupID: group})
	return membership(v), missing(e)
}
func (r reader) Memberships(store, user, group string) ([]d.Membership, error) {
	rows, e := r.q.ListMemberships(r.ctx, q.ListMembershipsParams{StoreID: store, UserID: user, GroupID: group})
	out := make([]d.Membership, 0, len(rows))
	for _, v := range rows {
		out = append(out, membership(v))
	}
	return out, e
}
func (w writer) PutMembership(v d.Membership) error {
	return w.q.PutMembership(w.ctx, q.PutMembershipParams{StoreID: v.StoreID, ID: v.ID, UserID: v.UserID, GroupID: v.GroupID, CloudformationOwner: v.CloudFormationOwner})
}
func (w writer) DeleteMembership(k d.Key) error {
	return w.q.DeleteMembership(w.ctx, q.DeleteMembershipParams{StoreID: k.StoreID, ID: k.ID})
}

var _ d.Repository = (*Repository)(nil)

func (w writer) DeleteStore(id string) error { return w.q.DeleteStore(w.ctx, id) }
