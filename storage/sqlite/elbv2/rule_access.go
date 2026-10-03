package elbv2

import (
	domain "stackd/storage/elbv2"
	"stackd/storage/sqlite/elbv2/internal/sqlcgen"
)

func (r reader) Rule(sc domain.Scope, a string) (domain.RuleRecord, error) {
	row, e := r.q.GetRule(r.ctx, sqlcgen.GetRuleParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a})
	if e != nil {
		return domain.RuleRecord{}, missing(e)
	}
	return r.rule(row)
}
func (r reader) Rules(sc domain.Scope) ([]domain.RuleRecord, error) {
	rows, e := r.q.ListRules(r.ctx, sqlcgen.ListRulesParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.RuleRecord, 0, len(rows))
	for _, row := range rows {
		v, e := r.rule(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) DeleteRule(sc domain.Scope, a string) error {
	if e := w.deleteTags(sc, a); e != nil {
		return e
	}
	return w.q.DeleteRule(w.ctx, sqlcgen.DeleteRuleParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a})
}
