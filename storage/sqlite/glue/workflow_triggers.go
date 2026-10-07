package glue

import (
	"database/sql"
	api "stackd/internal/awsapi/glue"
	domain "stackd/internal/services/glue"
	"stackd/storage/sqlite/glue/internal/sqlcgen"
)

func wfAction(job, crawler, security sql.NullString, timeout, delay sql.NullInt64) api.Action {
	a := api.Action{JobName: wfStringPtr[api.NameString](job), CrawlerName: wfStringPtr[api.NameString](crawler), SecurityConfiguration: wfStringPtr[api.NameString](security), Timeout: wfIntPtr[api.Timeout](timeout)}
	if delay.Valid {
		a.NotificationProperty = &api.NotificationProperty{NotifyDelayAfter: wfIntPtr[api.NotifyDelayAfter](delay)}
	}
	return a
}
func wfDelay(a api.Action) sql.NullInt64 {
	if a.NotificationProperty == nil {
		return sql.NullInt64{}
	}
	return wfInt(a.NotificationProperty.NotifyDelayAfter)
}
func wfCondition(job, crawler, state, crawl, logical sql.NullString) api.Condition {
	return api.Condition{JobName: wfStringPtr[api.NameString](job), CrawlerName: wfStringPtr[api.NameString](crawler), State: wfStringPtr[api.JobRunState](state), CrawlState: wfStringPtr[api.CrawlState](crawl), LogicalOperator: wfStringPtr[api.LogicalOperator](logical)}
}
func (r reader) Trigger(k domain.ResourceKey) (domain.TriggerRecord, error) {
	row, err := r.q.WFTriggerGet(r.ctx, sqlcgen.WFTriggerGetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.TriggerRecord{}, wfMissing(err)
	}
	return r.wfTrigger(row)
}
func (r reader) wfTrigger(row sqlcgen.GlueTrigger) (domain.TriggerRecord, error) {
	k := wfKey(row.Partition, row.AccountID, row.Region, row.Name)
	v := domain.TriggerRecord{Key: k, Trigger: api.Trigger{Name: new(api.NameString(k.Name)), Type: new(api.TriggerType(row.TriggerType)), State: new(api.TriggerState(row.State)), Description: wfStringPtr[api.DescriptionString](row.Description), Schedule: wfStringPtr[api.GenericString](row.Schedule), WorkflowName: wfStringPtr[api.NameString](row.WorkflowName), Actions: api.ActionList{}}, Tags: map[string]string{}, NextFire: wfTimePtr(row.NextFire)}
	v.CFNOwner = row.CfnOwner
	if row.PredicatePresent {
		v.Trigger.Predicate = &api.Predicate{Logical: wfStringPtr[api.Logical](row.PredicateLogical), Conditions: api.ConditionList{}}
	}
	tags, err := r.q.WFTriggerTagList(r.ctx, sqlcgen.WFTriggerTagListParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return v, err
	}
	for _, t := range tags {
		v.Tags[t.ItemKey] = t.ItemValue
	}
	actions, err := r.q.WFTriggerActionList(r.ctx, sqlcgen.WFTriggerActionListParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return v, err
	}
	for _, a := range actions {
		action := wfAction(a.JobName, a.CrawlerName, a.SecurityConfiguration, a.Timeout, a.NotificationDelay)
		args, err := r.q.WFTriggerArgumentList(r.ctx, sqlcgen.WFTriggerArgumentListParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Ordinal: a.Ordinal})
		if err != nil {
			return v, err
		}
		if len(args) > 0 {
			action.Arguments = api.GenericMap{}
			for _, arg := range args {
				action.Arguments[api.GenericString(arg.ItemKey)] = api.GenericString(arg.ItemValue)
			}
		}
		v.Trigger.Actions = append(v.Trigger.Actions, action)
	}
	conditions, err := r.q.WFTriggerConditionList(r.ctx, sqlcgen.WFTriggerConditionListParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return v, err
	}
	if v.Trigger.Predicate != nil {
		for _, c := range conditions {
			v.Trigger.Predicate.Conditions = append(v.Trigger.Predicate.Conditions, wfCondition(c.JobName, c.CrawlerName, c.State, c.CrawlState, c.LogicalOperator))
		}
	}
	return v, nil
}
func (r reader) Triggers(s domain.Scope) ([]domain.TriggerRecord, error) {
	rows, err := r.q.WFTriggerList(r.ctx, sqlcgen.WFTriggerListParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.TriggerRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.wfTrigger(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) NextTrigger() (domain.TriggerRecord, bool, error) {
	row, err := r.q.WFNextTrigger(r.ctx)
	if err == sql.ErrNoRows {
		return domain.TriggerRecord{}, false, nil
	}
	if err != nil {
		return domain.TriggerRecord{}, false, err
	}
	v, err := r.wfTrigger(row)
	return v, err == nil, err
}
func (w writer) PutTrigger(v domain.TriggerRecord) error {
	k := v.Key
	t := v.Trigger
	p := sqlcgen.WFTriggerPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, TriggerType: wfString(t.Type).String, State: wfString(t.State).String, Description: wfString(t.Description), Schedule: wfString(t.Schedule), WorkflowName: wfString(t.WorkflowName), NextFire: wfTime(v.NextFire), PredicatePresent: t.Predicate != nil}
	p.CfnOwner = v.CFNOwner
	if t.Predicate != nil {
		p.PredicateLogical = wfString(t.Predicate.Logical)
	}
	if err := w.q.WFTriggerPut(w.ctx, p); err != nil {
		return err
	}
	if err := w.q.WFTriggerTagDelete(w.ctx, sqlcgen.WFTriggerTagDeleteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for key, val := range v.Tags {
		if err := w.q.WFTriggerTagPut(w.ctx, sqlcgen.WFTriggerTagPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ItemKey: key, ItemValue: val}); err != nil {
			return err
		}
	}
	if err := w.q.WFTriggerActionDelete(w.ctx, sqlcgen.WFTriggerActionDeleteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for i, a := range t.Actions {
		if err := w.q.WFTriggerActionPut(w.ctx, sqlcgen.WFTriggerActionPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Ordinal: int64(i), JobName: wfString(a.JobName), CrawlerName: wfString(a.CrawlerName), SecurityConfiguration: wfString(a.SecurityConfiguration), Timeout: wfInt(a.Timeout), NotificationDelay: wfDelay(a)}); err != nil {
			return err
		}
		for key, val := range a.Arguments {
			if err := w.q.WFTriggerArgumentPut(w.ctx, sqlcgen.WFTriggerArgumentPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Ordinal: int64(i), ItemKey: string(key), ItemValue: string(val)}); err != nil {
				return err
			}
		}
	}
	if err := w.q.WFTriggerConditionDelete(w.ctx, sqlcgen.WFTriggerConditionDeleteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	if t.Predicate != nil {
		for i, c := range t.Predicate.Conditions {
			if err := w.q.WFTriggerConditionPut(w.ctx, sqlcgen.WFTriggerConditionPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Ordinal: int64(i), JobName: wfString(c.JobName), CrawlerName: wfString(c.CrawlerName), State: wfString(c.State), CrawlState: wfString(c.CrawlState), LogicalOperator: wfString(c.LogicalOperator)}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w writer) DeleteTrigger(k domain.ResourceKey) error {
	return w.q.WFTriggerDelete(w.ctx, sqlcgen.WFTriggerDeleteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
