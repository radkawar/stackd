package elbv2

import (
	domain "stackd/storage/elbv2"
	"stackd/storage/sqlite/elbv2/internal/sqlcgen"
)

func (r reader) LoadBalancer(sc domain.Scope, a string) (domain.LoadBalancerRecord, error) {
	row, e := r.q.GetLoadBalancer(r.ctx, sqlcgen.GetLoadBalancerParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a})
	if e != nil {
		return domain.LoadBalancerRecord{}, missing(e)
	}
	return r.loadBalancer(row)
}
func (r reader) LoadBalancers(sc domain.Scope) ([]domain.LoadBalancerRecord, error) {
	rows, e := r.q.ListLoadBalancers(r.ctx, sqlcgen.ListLoadBalancersParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.LoadBalancerRecord, 0, len(rows))
	for _, row := range rows {
		v, e := r.loadBalancer(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) DeleteLoadBalancer(sc domain.Scope, a string) error {
	if e := w.deleteTags(sc, a); e != nil {
		return e
	}
	if e := w.q.DeleteAttachments(w.ctx, sqlcgen.DeleteAttachmentsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a}); e != nil {
		return e
	}
	return w.q.DeleteLoadBalancer(w.ctx, sqlcgen.DeleteLoadBalancerParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a})
}
