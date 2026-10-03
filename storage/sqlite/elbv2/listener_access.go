package elbv2

import (
	domain "stackd/storage/elbv2"
	"stackd/storage/sqlite/elbv2/internal/sqlcgen"
)

func (r reader) Listener(sc domain.Scope, a string) (domain.ListenerRecord, error) {
	row, e := r.q.GetListener(r.ctx, sqlcgen.GetListenerParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a})
	if e != nil {
		return domain.ListenerRecord{}, missing(e)
	}
	return r.listener(row)
}
func (r reader) Listeners(sc domain.Scope) ([]domain.ListenerRecord, error) {
	rows, e := r.q.ListListeners(r.ctx, sqlcgen.ListListenersParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.ListenerRecord, 0, len(rows))
	for _, row := range rows {
		v, e := r.listener(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) DeleteListener(sc domain.Scope, a string) error {
	if e := w.deleteTags(sc, a); e != nil {
		return e
	}
	return w.q.DeleteListener(w.ctx, sqlcgen.DeleteListenerParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a})
}
