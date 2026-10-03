package elbv2

import (
	domain "stackd/storage/elbv2"
	"stackd/storage/sqlite/elbv2/internal/sqlcgen"
)

func target(row sqlcgen.Elbv2Target) domain.TargetRecord {
	v := domain.TargetRecord{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, TargetGroupARN: row.Arn, OwnerARN: row.OwnerArn, Incarnation: row.Incarnation, State: row.State, Reason: row.Reason, Description: row.Description, Successes: int(row.Successes), Failures: int(row.Failures), NextCheck: readTime(row.NextCheck), DrainUntil: readTime(row.DrainUntil), Version: uint64(row.Version)}
	text(&v.Data.Id, row.TargetID)
	number(&v.Data.Port, row.Port)
	text(&v.Data.AvailabilityZone, row.AvailabilityZone)
	return v
}
func (r reader) Target(sc domain.Scope, a, id string, port int32) (domain.TargetRecord, error) {
	row, e := r.q.GetTarget(r.ctx, sqlcgen.GetTargetParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a, TargetID: id, Port: int64(port)})
	if e != nil {
		return domain.TargetRecord{}, missing(e)
	}
	return target(row), nil
}
func (r reader) Targets(sc domain.Scope, a string) ([]domain.TargetRecord, error) {
	rows, e := r.q.ListTargets(r.ctx, sqlcgen.ListTargetsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a})
	if e != nil {
		return nil, e
	}
	out := make([]domain.TargetRecord, len(rows))
	for i, row := range rows {
		out[i] = target(row)
	}
	return out, nil
}
func (w writer) PutTarget(v domain.TargetRecord) error {
	return w.q.PutTarget(w.ctx, sqlcgen.PutTargetParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: v.TargetGroupARN, TargetID: value(v.Data.Id), Port: intValue(v.Data.Port), AvailabilityZone: value(v.Data.AvailabilityZone), OwnerArn: v.OwnerARN, Incarnation: v.Incarnation, State: v.State, Reason: v.Reason, Description: v.Description, Successes: int64(v.Successes), Failures: int64(v.Failures), NextCheck: timeValue(v.NextCheck), DrainUntil: timeValue(v.DrainUntil), Version: int64(v.Version)})
}
func (w writer) DeleteTarget(sc domain.Scope, a, id string, port int32) error {
	return w.q.DeleteTarget(w.ctx, sqlcgen.DeleteTargetParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a, TargetID: id, Port: int64(port)})
}
