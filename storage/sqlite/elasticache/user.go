package elasticache

import (
	domain "stackd/storage/elasticache"
	"stackd/storage/sqlite/elasticache/internal/sqlcgen"
)

func (r reader) User(k domain.Key) (domain.User, error) {
	row, e := r.q.GetUser(r.ctx, sqlcgen.GetUserParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return domain.User{}, missing(e)
	}
	return r.user(row)
}
func (r reader) Users(sc domain.Scope) ([]domain.User, error) {
	rows, e := r.q.ListUsers(r.ctx, sqlcgen.ListUsersParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.User, 0, len(rows))
	for _, row := range rows {
		v, e := r.user(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) user(row sqlcgen.ElasticacheUser) (domain.User, error) {
	v := domain.User{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: row.Kind, Name: row.Name}, Name: row.UserName, Engine: row.Engine, AccessString: row.AccessString, Status: row.Status, NoPassword: row.NoPassword != 0, CloudFormationOwner: row.CloudformationOwner}
	var e error
	v.Tags, e = r.tags(v.Key)
	if e != nil {
		return v, e
	}
	v.PasswordHashes, e = r.hashes(v.Key)
	if e != nil {
		return v, e
	}
	return v, nil
}
func (w writer) PutUser(v domain.User) error {
	k := v.Key
	if e := w.q.PutUser(w.ctx, sqlcgen.PutUserParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, UserName: v.Name, Engine: v.Engine, AccessString: v.AccessString, Status: v.Status, NoPassword: bit(v.NoPassword), CloudformationOwner: v.CloudFormationOwner}); e != nil {
		return e
	}
	if e := w.putTags(k, v.Tags); e != nil {
		return e
	}
	if e := w.putHashes(k, v.PasswordHashes); e != nil {
		return e
	}
	return nil
}
func (w writer) DeleteUser(k domain.Key) error {
	if e := w.deleteChildren(k); e != nil {
		return e
	}
	return w.q.DeleteUser(w.ctx, sqlcgen.DeleteUserParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
}
