package elasticache

import (
	domain "stackd/storage/elasticache"
	"stackd/storage/sqlite/elasticache/internal/sqlcgen"
)

func (r reader) UserGroup(k domain.Key) (domain.UserGroup, error) {
	row, e := r.q.GetUserGroup(r.ctx, sqlcgen.GetUserGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return domain.UserGroup{}, missing(e)
	}
	return r.usergroup(row)
}
func (r reader) UserGroups(sc domain.Scope) ([]domain.UserGroup, error) {
	rows, e := r.q.ListUserGroups(r.ctx, sqlcgen.ListUserGroupsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.UserGroup, 0, len(rows))
	for _, row := range rows {
		v, e := r.usergroup(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) usergroup(row sqlcgen.ElasticacheUserGroup) (domain.UserGroup, error) {
	v := domain.UserGroup{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: row.Kind, Name: row.Name}, Engine: row.Engine, Status: row.Status}
	var e error
	v.Tags, e = r.tags(v.Key)
	if e != nil {
		return v, e
	}
	v.UserIDs, e = r.members(v.Key)
	if e != nil {
		return v, e
	}
	return v, nil
}
func (w writer) PutUserGroup(v domain.UserGroup) error {
	k := v.Key
	if e := w.q.PutUserGroup(w.ctx, sqlcgen.PutUserGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, Engine: v.Engine, Status: v.Status}); e != nil {
		return e
	}
	if e := w.putTags(k, v.Tags); e != nil {
		return e
	}
	if e := w.putMembers(k, v.UserIDs); e != nil {
		return e
	}
	return nil
}
func (w writer) DeleteUserGroup(k domain.Key) error {
	if e := w.deleteChildren(k); e != nil {
		return e
	}
	return w.q.DeleteUserGroup(w.ctx, sqlcgen.DeleteUserGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
}
