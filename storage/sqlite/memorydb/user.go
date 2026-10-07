package memorydb

import (
	domain "stackd/storage/memorydb"
	"stackd/storage/sqlite/memorydb/internal/sqlcgen"
)

func (r reader) readUser(row sqlcgen.MemorydbUser) (domain.User, error) {
	v := domain.User{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: "user", Name: row.Name}, AccessString: row.AccessString, Authentication: row.Authentication, Status: row.Status, CloudFormationOwner: row.CloudformationOwner}
	var e error
	v.Tags, e = r.tags(row.Arn)
	if e != nil {
		return v, e
	}
	if e = r.readPasswordHash(&v); e != nil {
		return v, e
	}
	return v, nil
}
func (r reader) User(k domain.Key) (domain.User, error) {
	row, e := r.q.GetUser(r.ctx, k.ARN())
	if e != nil {
		return domain.User{}, missing(e)
	}
	return r.readUser(row)
}
func (r reader) Users(sc domain.Scope) ([]domain.User, error) {
	rows, e := r.q.ListUser(r.ctx, sqlcgen.ListUserParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.User, 0, len(rows))
	for _, row := range rows {
		v, e := r.readUser(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutUser(v domain.User) error {
	if e := w.q.PutUser(w.ctx, sqlcgen.PutUserParams{Arn: v.Key.ARN(), Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name, AccessString: v.AccessString, Authentication: v.Authentication, Status: v.Status, CloudformationOwner: v.CloudFormationOwner}); e != nil {
		return e
	}
	if e := w.putTags(v.Key.ARN(), v.Tags); e != nil {
		return e
	}
	return w.putPasswordHash(v)
}
func (w writer) DeleteUser(k domain.Key) error {
	if e := w.q.ClearTag(w.ctx, k.ARN()); e != nil {
		return e
	}
	if e := w.q.ClearPasswordHash(w.ctx, k.ARN()); e != nil {
		return e
	}
	return w.q.DeleteUser(w.ctx, k.ARN())
}
