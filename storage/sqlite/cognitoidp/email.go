package cognitoidp

import (
	domain "stackd/storage/cognitoidp"
	"stackd/storage/sqlite/cognitoidp/internal/sqlcgen"
)

func (r reader) EmailCode(k domain.EmailCodeKey) (domain.EmailCodeRecord, error) {
	v, e := r.q.GetEmailCode(r.ctx, sqlcgen.GetEmailCodeParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Username: k.Username, Kind: k.Kind})
	if e != nil {
		return domain.EmailCodeRecord{}, missing(e)
	}
	return domain.EmailCodeRecord{Key: k, Expires: v.Expires.UTC(), Digest: v.Digest}, nil
}
func (w writer) PutEmailCode(v domain.EmailCodeRecord) error {
	k := v.Key
	return w.q.PutEmailCode(w.ctx, sqlcgen.PutEmailCodeParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Username: k.Username, Kind: k.Kind, Expires: v.Expires.UTC(), Digest: v.Digest})
}
func (w writer) DeleteEmailCode(k domain.EmailCodeKey) error {
	return w.q.DeleteEmailCode(w.ctx, sqlcgen.DeleteEmailCodeParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Username: k.Username, Kind: k.Kind})
}
