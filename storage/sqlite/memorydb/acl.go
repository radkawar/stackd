package memorydb

import (
	domain "stackd/storage/memorydb"
	"stackd/storage/sqlite/memorydb/internal/sqlcgen"
)

func (r reader) readACL(row sqlcgen.MemorydbAcl) (domain.ACL, error) {
	v := domain.ACL{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: "acl", Name: row.Name}, Status: row.Status, CloudFormationOwner: row.CloudformationOwner}
	var e error
	v.Tags, e = r.tags(row.Arn)
	if e != nil {
		return v, e
	}
	if e = r.readACLUser(&v); e != nil {
		return v, e
	}
	return v, nil
}
func (r reader) ACL(k domain.Key) (domain.ACL, error) {
	row, e := r.q.GetACL(r.ctx, k.ARN())
	if e != nil {
		return domain.ACL{}, missing(e)
	}
	return r.readACL(row)
}
func (r reader) ACLs(sc domain.Scope) ([]domain.ACL, error) {
	rows, e := r.q.ListACL(r.ctx, sqlcgen.ListACLParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.ACL, 0, len(rows))
	for _, row := range rows {
		v, e := r.readACL(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutACL(v domain.ACL) error {
	if e := w.q.PutACL(w.ctx, sqlcgen.PutACLParams{Arn: v.Key.ARN(), Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name, Status: v.Status, CloudformationOwner: v.CloudFormationOwner}); e != nil {
		return e
	}
	if e := w.putTags(v.Key.ARN(), v.Tags); e != nil {
		return e
	}
	return w.putACLUser(v)
}
func (w writer) DeleteACL(k domain.Key) error {
	if e := w.q.ClearTag(w.ctx, k.ARN()); e != nil {
		return e
	}
	if e := w.q.ClearACLUser(w.ctx, k.ARN()); e != nil {
		return e
	}
	return w.q.DeleteACL(w.ctx, k.ARN())
}
