package elbv2

import (
	domain "stackd/storage/elbv2"
	"stackd/storage/sqlite/elbv2/internal/sqlcgen"
)

func (r reader) TargetGroup(sc domain.Scope, a string) (domain.TargetGroupRecord, error) {
	row, e := r.q.GetTargetGroup(r.ctx, sqlcgen.GetTargetGroupParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a})
	if e != nil {
		return domain.TargetGroupRecord{}, missing(e)
	}
	return r.targetGroup(row)
}
func (r reader) TargetGroups(sc domain.Scope) ([]domain.TargetGroupRecord, error) {
	rows, e := r.q.ListTargetGroups(r.ctx, sqlcgen.ListTargetGroupsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.TargetGroupRecord, 0, len(rows))
	for _, row := range rows {
		v, e := r.targetGroup(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) DeleteTargetGroup(sc domain.Scope, a string) error {
	if e := w.deleteTags(sc, a); e != nil {
		return e
	}
	return w.q.DeleteTargetGroup(w.ctx, sqlcgen.DeleteTargetGroupParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a})
}
